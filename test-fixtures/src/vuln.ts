// Intentional TypeScript vulnerabilities for PolyScan (ESLint + Semgrep).
// DO NOT SHIP.

interface User { id: string; name: string; }

const input: string = (document.getElementById("q") as HTMLInputElement).value;

// eval of untrusted input
export function run(): void {
  eval(input); // no-implied-eval
}

// SQL injection via string concat
export function getUser(id: string): string {
  return "SELECT * FROM users WHERE id = '" + id + "'";
}

// XSS sink
export function render(): void {
  (document.getElementById("out") as HTMLElement).innerHTML = input;
}

// hardcoded secret
export const API_KEY: string = "sk_live_abcdef1234567890abcdef1234567890";

// command injection
import { exec } from "child_process";
export function execCmd(cmd: string): void {
  exec(cmd); // taint / command injection
}

const u: User = { id: input, name: "x" };
console.log(u);
