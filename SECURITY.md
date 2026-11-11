# Security Notice

## This project is intentionally insecure

This lab contains:

- **DVWA** — a deliberately vulnerable web application with SQL injection,
  reflected/stored XSS, command injection, file upload, and more.
- **WeakWAF** — a reverse proxy with intentionally naive filtering logic.
- **OWASP CRS / ModSecurity** — a real WAF, included for comparison.

These components exist to teach WAF evasion in a controlled environment.
They are **not** production software and must not be deployed as security
controls.

## Deployment rules

1. Bind to `127.0.0.1` (the default) or a single isolated lab interface.
2. Never expose this stack to the public internet.
3. If LAN access is required, restrict it with a host firewall to the lab
   subnet only.
4. Tear the stack down when finished: `docker compose down -v`.
5. Do not store real credentials, customer data, or production secrets in
   the lab.

## Reporting issues

This is an educational project with no security support commitment. If you
find a problem in the **lab's own code** (for example, a bug that causes
unintended host exposure), open a GitHub issue.

Do **not** use this repository's issue tracker to report vulnerabilities in
DVWA, ModSecurity, OWASP CRS, or Docker images — report those upstream to
their respective maintainers.
