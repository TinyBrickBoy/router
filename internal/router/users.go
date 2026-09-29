package router

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/tinybrickboy/router/internal/store"
)

// validUsername erlaubt Buchstaben, Ziffern und . _ - @
func validUsername(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-@", c)) {
			return false
		}
	}
	return true
}

func validRole(v string) bool { return v == store.RoleAdmin || v == store.RoleViewer }

func (s *Server) userAdd(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("username"))
	err := s.Store.Update(func(st *store.State) error {
		if !validUsername(name) {
			return fmt.Errorf("benutzername ungültig (buchstaben, ziffern, . _ - @)")
		}
		if st.User(name) != nil {
			return fmt.Errorf("benutzer %s existiert bereits", name)
		}
		role := r.FormValue("role")
		if !validRole(role) {
			return fmt.Errorf("unbekannte rolle")
		}
		pw := r.FormValue("password")
		if len(pw) < passwordMinLen {
			return fmt.Errorf("passwort muss mindestens %d zeichen haben", passwordMinLen)
		}
		u := store.User{Username: name, Role: role}
		if err := SetPassword(&u, pw); err != nil {
			return err
		}
		st.Users = append(st.Users, u)
		sort.Slice(st.Users, func(i, j int) bool { return st.Users[i].Username < st.Users[j].Username })
		return nil
	})
	s.done(w, r, "/settings", err, "Benutzer "+name+" angelegt")
}

// extraUser sucht einen zusätzlichen Benutzer. Der Hauptbenutzer ist hier bewusst nicht enthalten.
func extraUser(st *store.State, name string) (int, error) {
	for i := range st.Users {
		if st.Users[i].Username == name {
			return i, nil
		}
	}
	if name == st.Admin.Username {
		return 0, fmt.Errorf("der hauptbenutzer %s ist immer admin und kann nicht gelöscht werden", name)
	}
	return 0, fmt.Errorf("benutzer nicht gefunden")
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := s.Store.Update(func(st *store.State) error {
		i, err := extraUser(st, name)
		if err != nil {
			return err
		}
		st.Users = append(st.Users[:i], st.Users[i+1:]...)
		return nil
	})
	s.done(w, r, "/settings", err, "Benutzer "+name+" gelöscht")
}

func (s *Server) userRole(w http.ResponseWriter, r *http.Request) {
	name, role := r.PathValue("name"), r.FormValue("role")
	err := s.Store.Update(func(st *store.State) error {
		i, err := extraUser(st, name)
		if err != nil {
			return err
		}
		if !validRole(role) {
			return fmt.Errorf("unbekannte rolle")
		}
		st.Users[i].Role = role
		return nil
	})
	s.done(w, r, "/settings", err, "Rolle von "+name+" ist jetzt "+role)
}

// userPassword setzt das Passwort eines anderen Benutzers (nur Admins).
func (s *Server) userPassword(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := s.Store.Update(func(st *store.State) error {
		i, err := extraUser(st, name)
		if err != nil {
			return err
		}
		pw := r.FormValue("password")
		if len(pw) < passwordMinLen {
			return fmt.Errorf("passwort muss mindestens %d zeichen haben", passwordMinLen)
		}
		return SetPassword(&st.Users[i], pw)
	})
	s.done(w, r, "/settings", err, "Passwort von "+name+" gesetzt")
}
