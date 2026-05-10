# Linux Kernel CVE Check — Ansible Playbooks

Ansible Playbooks zur Inventarisierung und Schwachstellenprüfung von Ubuntu Linux Servern.

> **Hinweis:** Diese Playbooks sind ein Hilfsmittel für Administratoren und ersetzen keine offizielle Sicherheitsbewertung. Die Ergebnisse sind Indikatoren, keine garantierten Aussagen. Siehe [Einschränkungen](#einschränkungen--haftungsausschluss).

---

## Inhalt

| Datei | Zweck |
|---|---|
| [`check_kernel_cves.yml`](#2-cve-schwachstellenprüfung) | Prüft auf Copy Fail & Dirty Frag Kernel-Schwachstellen |
| [`inventory.ini`](#inventory-konfiguration) | Beispiel-Inventory mit Zielservern |

---

## Voraussetzungen

- **Ansible** ≥ 2.12 auf dem Control Node
- **Ubuntu** 18.04 / 20.04 / 22.04 / 24.04 auf den Zielservern
- SSH-Zugang mit Public-Key-Authentifizierung (empfohlen)
- `sudo`-Berechtigung für den Ansible-User (für wenige lesende Root-Operationen)
- Auf den Zielservern: `python3`, `lsb_release`, `dpkg`

```bash
# Ansible installieren (Control Node)
pip install ansible
```

---

## Inventory konfigurieren

Passe `inventory.ini` an deine Umgebung an:

```ini
[ubuntu_servers]
server1 ansible_host=192.168.1.10 ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/id_rsa
server2 ansible_host=192.168.1.11 ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/id_rsa

[ubuntu_servers:vars]
ansible_python_interpreter=/usr/bin/python3
```

Verbindung testen:

```bash
ansible -i inventory.ini all -m ping
```

---

## CVE-Schwachstellenprüfung

**Datei:** `check_kernel_cves.yml`

Prüft Ubuntu Server auf Anfälligkeit für zwei kritische Linux-Kernel-Schwachstellen aus 2026. Das Playbook ist **vollständig read-only** — es werden keine Änderungen, Konfigurationen oder Patches eingespielt.

---

### Geprüfte Schwachstellen

#### CVE-2026-31431 — »Copy Fail«

| | |
|---|---|
| **CVSS** | 9.8 (Kritisch) |
| **Angriffsvektor** | Lokal (kein Netzwerkzugang erforderlich) |
| **Betroffen** | Linux Kernel 4.14 – 6.19.12 |
| **Fix** | Mainline-Commit `a664bf3d603d`, gemergt 01. April 2026 |
| **Komponente** | `algif_aead` — AF_ALG AEAD Krypto-Interface |

**Was passiert bei einem Angriff?**
Ein unprivilegierter lokaler Benutzer kann über das `AF_ALG`-Socket-Interface in Kombination mit `splice()` einen kontrollierten 4-Byte-Write in den Page Cache erzwingen. Damit lassen sich SUID-Binaries im Speicher korrumpieren — ohne die Seiten als "dirty" zu markieren. Die Manipulation ist systemweit sofort sichtbar und ermöglicht eine zuverlässige Eskalation zu `root`.

**Betroffene Ubuntu-Versionen:**

| Ubuntu Release | Sicher ab Kernel-Paket |
|---|---|
| 18.04 LTS (Bionic) | `4.15.0-233.245` |
| 20.04 LTS (Focal) | `5.4.0-211.231` |
| 22.04 LTS (Jammy) | `5.15.0-137.147` |
| 24.04 LTS (Noble) | `6.8.0-60.63` |
| 26.04+ | Nicht betroffen |

---

#### CVE-2026-43284 + CVE-2026-43500 — »Dirty Frag«

| | |
|---|---|
| **CVSS** | 9.1 (Kritisch) |
| **Angriffsvektor** | Lokal |
| **Komponenten** | `esp4` / `esp6` (IPsec) und `rxrpc` (RxRPC) |

**CVE-2026-43284 — IPsec ESP**

Fehler in den In-place-Dekryptierungs-Fastpaths von `esp4`/`esp6`. Wenn Socket-Buffer paged Fragments tragen, die nicht exklusiv dem Kernel gehören (via `splice(2)` / `sendfile(2)` / `MSG_SPLICE_PAGES`), dekryptiert der Receive-Path direkt über extern-referenzierte Pages. Dies erzeugt ein Schreibprimitiv in den Page Cache.

- **Betroffen:** Kernel 4.14 bis Fix (gemergt 07. Mai 2026)
- **Patch verfügbar:** Ja (Ubuntu 20.04 / 22.04 / 24.04)

| Ubuntu Release | Sicher ab Kernel-Paket |
|---|---|
| 20.04 LTS (Focal) | `5.4.0-214.234` |
| 22.04 LTS (Jammy) | `5.15.0-139.149` |
| 24.04 LTS (Noble) | `6.8.0-62.65` |

**CVE-2026-43500 — RxRPC**

Identisches Problem im RxRPC-In-place-Dekryptierungs-Fastpath. Nur relevant für Kernel ≥ 6.4 (Vulnerability eingeführt Juni 2023).

- **Betroffen:** Kernel ≥ 6.4
- **Patch verfügbar:** Nein (Stand: Mai 2026 — kein offizieller Upstream-Fix)

---

### Erkennungslogik

Das Playbook kombiniert drei unabhängige Prüfmethoden:

```
1. Kernel-Config (/boot/config-* oder /proc/config.gz)
   → Ist das Modul eingebaut (=y) oder ladbar (=m)?

2. lsmod
   → Ist das Modul gerade aktiv geladen?

3. dpkg-Versionsvergleich
   → Ist das installierte Kernel-Paket bereits gepatcht?
```

**Ergebnis-Kategorien:**

| Ausgabe | Bedeutung | Handlungsbedarf |
|---|---|---|
| `YES – Ungepatcht UND Modul aktiv` | Modul läuft, Kernel nicht gepatcht | **Sofort** |
| `WAHRSCHEINLICH` | Modul aktiv, Kernel-Version nicht prüfbar | Dringend |
| `BEDINGT` | Modul ladbar, aber aktuell nicht geladen | Empfohlen |
| `NO – Kernel gepatcht` | Gepatchte Version installiert | Keiner |
| `GERING` | Modul nicht vorhanden | Keiner |

---

### Verwendung

```bash
# Alle CVEs prüfen
ansible-playbook -i inventory.ini check_kernel_cves.yml

# Nur Copy Fail prüfen
ansible-playbook -i inventory.ini check_kernel_cves.yml --tags copyfail

# Nur Dirty Frag prüfen
ansible-playbook -i inventory.ini check_kernel_cves.yml --tags dirtyfrag

# Einen einzelnen Host prüfen
ansible-playbook -i inventory.ini check_kernel_cves.yml --limit server1

# Verbose-Ausgabe für Debugging
ansible-playbook -i inventory.ini check_kernel_cves.yml -v
```

---

### Worauf ist zu achten?

**Kernel-Config nicht gefunden**
Ist weder `/boot/config-$(uname -r)` noch `/proc/config.gz` vorhanden, kann das Playbook nur auf `lsmod` zurückgreifen. Die Erkennung ist dann weniger präzise — ein nicht geladenes, aber eingebautes Modul wird nicht erkannt.

```bash
# Auf dem Zielserver prüfen ob Config vorhanden ist
ls /boot/config-$(uname -r)
zcat /proc/config.gz > /dev/null 2>&1 && echo "vorhanden"
```

**Kernel-Paket nicht in dpkg**
Bei manuell kompilierten oder aus Drittquellen installierten Kerneln liefert `dpkg-query` keinen Treffer. Die Versionsvergleich-Stufe gibt dann `UNKNOWN` aus — die Modul-Checks bleiben aber weiterhin gültig.

**CVE-2026-43500 — kein Patch verfügbar**
Für die RxRPC-Komponente von Dirty Frag existiert zum Zeitpunkt der Erstellung (Mai 2026) noch kein offizieller Upstream-Patch. Als temporäre Abhilfe kann das Modul deaktiviert werden — dies bricht jedoch AFS-Distributed-Filesystem-Setups.

**`become: true` Scope**
Das Playbook setzt Root-Rechte nur für eine einzige Task: das Lesen der Kernel-Config aus `/boot/`. Alle anderen Tasks laufen ohne erhöhte Rechte.

---

## Einschränkungen & Haftungsausschluss

> Diese Playbooks sind **Administrationshilfen**, kein Ersatz für ein professionelles Vulnerability-Management oder eine offizielle Sicherheitsbewertung.

- Die gepatchten Kernel-Paketversionen basieren auf Ubuntu Security Notices und können sich ändern. Prüfe regelmäßig unter [ubuntu.com/security/notices](https://ubuntu.com/security/notices) auf aktuellere Versionen.
- Ein Ergebnis `NO – Kernel gepatcht` bedeutet, dass der **installierte** Kernel gepatcht ist. Es wird **nicht** geprüft, ob dieser Kernel auch **aktiv gebootet** ist (`uname -r` vs. installiertes Paket).
- Module die zur Laufzeit per `LD_PRELOAD` oder andere Mechanismen geladen werden, werden nicht erkannt.
- Neue CVEs oder Kernel-Regressionen nach Patch-Datum werden nicht abgedeckt.
- Der Befund `GERING` bedeutet nur, dass das Modul aktuell nicht verfügbar ist — nicht, dass das System generell sicher ist.

**Empfehlung:** Nutze diese Playbooks als ersten schnellen Überblick und kombiniere sie mit:
- `unattended-upgrades` für automatische Sicherheitsupdates
- Ubuntu Pro / Livepatch für Kernel-Updates ohne Neustart
- Einem Vulnerability-Scanner (OpenVAS, Trivy, Tenable) für tiefergehende Analysen

---

## Referenzen

| Ressource | Link |
|---|---|
| Ubuntu CVE Tracker — Copy Fail | https://ubuntu.com/security/CVE-2026-31431 |
| Ubuntu CVE Tracker — Dirty Frag ESP | https://ubuntu.com/security/CVE-2026-43284 |
| Ubuntu CVE Tracker — Dirty Frag RxRPC | https://ubuntu.com/security/CVE-2026-43500 |
| Ubuntu Security Notices | https://ubuntu.com/security/notices |
| Ubuntu Pro / Livepatch | https://ubuntu.com/security/livepatch |
| NVD — Copy Fail | https://nvd.nist.gov/vuln/detail/CVE-2026-31431 |
| NVD — Dirty Frag ESP | https://nvd.nist.gov/vuln/detail/CVE-2026-43284 |
| NVD — Dirty Frag RxRPC | https://nvd.nist.gov/vuln/detail/CVE-2026-43500 |
