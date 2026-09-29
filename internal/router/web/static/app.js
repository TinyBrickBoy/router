// Kleine Helfer ohne Inline JavaScript (Content Security Policy: script-src 'self').
document.addEventListener('submit', function (e) {
  var msg = e.target.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) e.preventDefault();
}, true);

document.addEventListener('click', function (e) {
  var t = e.target;
  if (t.hasAttribute('data-select')) t.select();
  if (t.hasAttribute('data-copy')) {
    var input = t.previousElementSibling;
    navigator.clipboard.writeText(input.value).then(function () { t.textContent = 'Kopiert'; });
  }
});

document.addEventListener('change', function (e) {
  if (e.target.hasAttribute('data-autosubmit')) e.target.form.requestSubmit();
});
