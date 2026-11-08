// Intentional vulnerabilities for PolyScan testing (ESLint / Semgrep).
// DO NOT SHIP.
const userInput = document.getElementById("q").value;

// eval of untrusted input
function run() {
  eval(userInput); // no-eval / no-implied-eval
}

// string-evaluating timer and global eval (need oxlint's browser/node environments)
function schedule() {
  setTimeout("alert(document.cookie)", 0); // no-implied-eval
  window.eval(userInput); // no-eval
}

// innerHTML XSS sink
function render() {
  document.getElementById("out").innerHTML = userInput; // xss
}

// SQL string concatenation
function query(id) {
  const sql = "SELECT * FROM users WHERE id = '" + id + "'";
  return sql;
}

// hardcoded secret
const API_KEY = "sk_live_abcdef1234567890abcdef1234567890";

module.exports = { run, render, query, API_KEY };
