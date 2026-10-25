package netcfg

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ReplyChain markiert Verbindungen, die über den Tunnel ankommen.
const ReplyChain = "BGP-AGENT-REPLY"

// SyncReplyMark sorgt dafür, dass Antworten auf Verbindungen, die über iface
// ankommen, auch dann über den Tunnel zurückgehen, wenn sie nicht von einer
// zugewiesenen IP stammen. Das betrifft vor allem Docker: bei DNAT auf einen
// Container wird die Absenderadresse der Antwort erst nach der Routing
// Entscheidung auf die zugewiesene IP zurückgeschrieben, die "from" Policy
// Rule greift also nie und die Antworten gingen übers normale Netz raus.
//
// Neue Verbindungen von iface bekommen mark als Connmark, Pakete dieser
// Verbindungen aus anderen Interfaces (die Antworten) das mark als fwmark,
// und eine fwmark Rule mit priority schickt sie in table. Nur die Bits von
// mark werden gesetzt und verglichen, andere Marks bleiben unberührt.
// Bestehende Verbindungen behalten ihren Weg, nur neue werden markiert.
//
// tool ist iptables oder ip6tables; fehlt es, passiert nichts (ohne Regeln
// gibt es auch nichts zu korrigieren). enable=false entfernt alles wieder.
func (m *Manager) SyncReplyMark(tool, iface string, mark uint32, table string, priority int, enable bool) error {
	if !m.R.DryRun {
		if _, err := exec.LookPath(tool); err != nil {
			return nil
		}
	}
	fam := "-4"
	if tool == "ip6tables" {
		fam = "-6"
	}
	if err := m.syncMarkRule(fam, mark, table, priority, enable); err != nil {
		return err
	}

	if !enable {
		// fehlende Kette/Sprung ist kein Fehler: dann ist nichts zu entfernen
		m.R.Run(tool, "-w", "-t", "mangle", "-D", "PREROUTING", "-j", ReplyChain) //nolint:errcheck
		m.R.Run(tool, "-w", "-t", "mangle", "-F", ReplyChain)                     //nolint:errcheck
		m.R.Run(tool, "-w", "-t", "mangle", "-X", ReplyChain)                     //nolint:errcheck
		return nil
	}

	mk := fmt.Sprintf("0x%x/0x%x", mark, mark)
	rules := [][]string{
		{"-A", ReplyChain, "-i", iface, "-m", "conntrack", "--ctstate", "NEW", "-j", "CONNMARK", "--set-xmark", mk},
		{"-A", ReplyChain, "!", "-i", iface, "-m", "connmark", "--mark", mk, "-j", "MARK", "--set-xmark", mk},
	}
	want := []string{"-N " + ReplyChain}
	for _, r := range rules {
		want = append(want, strings.Join(r, " "))
	}
	out, err := m.R.Query(tool, "-w", "-t", "mangle", "-S", ReplyChain)
	if err != nil {
		if _, err := m.R.Run(tool, "-w", "-t", "mangle", "-N", ReplyChain); err != nil {
			return err
		}
		out = ""
	}
	if strings.Join(strings.Fields(out), " ") != strings.Join(want, " ") {
		if _, err := m.R.Run(tool, "-w", "-t", "mangle", "-F", ReplyChain); err != nil {
			return err
		}
		for _, r := range rules {
			if _, err := m.R.Run(tool, append([]string{"-w", "-t", "mangle"}, r...)...); err != nil {
				return err
			}
		}
	}
	if _, err := m.R.Query(tool, "-w", "-t", "mangle", "-C", "PREROUTING", "-j", ReplyChain); err != nil || m.R.DryRun {
		// vorne einhängen, damit kein späteres ACCEPT/RETURN die Markierung verhindert
		_, err := m.R.Run(tool, "-w", "-t", "mangle", "-I", "PREROUTING", "1", "-j", ReplyChain)
		return err
	}
	return nil
}

// syncMarkRule setzt genau eine "fwmark mark/mark lookup table" Rule mit priority.
func (m *Manager) syncMarkRule(fam string, mark uint32, table string, priority int, enable bool) error {
	prio := strconv.Itoa(priority)
	mk := fmt.Sprintf("0x%x/0x%x", mark, mark)
	found := false
	out, err := m.R.Query("ip", "-j", fam, "rule", "show")
	if err == nil && strings.TrimSpace(out) != "" {
		var entries []struct {
			Priority int    `json:"priority"`
			Fwmark   string `json:"fwmark"`
			Fwmask   string `json:"fwmask"`
			Table    any    `json:"table"`
		}
		if err := json.Unmarshal([]byte(out), &entries); err != nil {
			return fmt.Errorf("ip rule parsen: %w", err)
		}
		for _, e := range entries {
			if e.Priority != priority || e.Fwmark == "" {
				continue
			}
			cur := e.Fwmark
			if e.Fwmask != "" {
				cur += "/" + e.Fwmask
			}
			if enable && !found && cur == mk && fmt.Sprint(e.Table) == table {
				found = true
				continue
			}
			if _, err := m.R.Run("ip", fam, "rule", "del", "priority", prio, "fwmark", cur); err != nil {
				return err
			}
		}
	}
	if enable && !found {
		_, err := m.R.Run("ip", fam, "rule", "add", "priority", prio, "fwmark", mk, "table", table)
		return err
	}
	return nil
}
