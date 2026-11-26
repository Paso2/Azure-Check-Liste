# Kapitel 12: Bewertung, Reporting, Finding-Template & Master-Checkliste

Dieses Kapitel unterstützt die strukturierte **Auswertung** der gesammelten Befunde, eine konsistente **Risikobewertung** nach CIS Benchmarks sowie eine **Master-Checkliste zum Abhaken** für jedes Kunden-Assessment.

---

## 12.1 Risikobewertungs-Schema

| Schweregrad | Kriterien & Praxisbeispiele | Typischer Zielzeitraum |
| :--- | :--- | :--- |
| 🔴 **Kritisch (Critical)** | Sofort ausnutzbare Schwachstellen mit Tenant-/Subscription-weiter Auswirkung (z. B. fehlende MFA für Global Admins, offenes Legacy Auth ohne CA, RDP/SSH `0.0.0.0/0` auf produktive VMs, öffentlicher Storage-Container mit sensiblen Daten, SQL Firewall `0.0.0.0` ohne Entra-Only, ungeschützte hochprivilegierte OAuth-App, Power BI „Publish to Web“ mit sensiblen Daten) | **Sofort (0–7 Tage)** |
| 🟠 **Hoch (High)** | Grobe Abweichungen von CIS Level 1 mit hohem Schadenspotenzial (z. B. > 4 dauerhafte Global Admins, On-Prem-gesyncte Admins, User Consent für Apps erlaubt, fehlendes Unified Audit Log, fehlende DMARC-Durchsetzung `p=none`, SMTP AUTH aktiv, externe Auto-Weiterleitung erlaubt, Teams Unmanaged Users aktiv, Key Vault ohne Purge Protection) | **Kurzfristig (≤ 30 Tage)** |
| 🟡 **Mittel (Medium)** | CIS Level 1/2 Härtungsdefizite (Defense-in-Depth), z. B. fehlende Activity Log Alerts, fehlende VNet Flow Logs, fehlendes Defender for Cloud Plan-Coverage, SharePoint Default Link „Edit“, fehlendes Idle Session Timeout, fehlende Intune „Not compliant“-Default-Einstellung | **Mittelfristig (≤ 90 Tage)** |
| 🔵 **Niedrig / Hinweis (Low / Info)** | CIS Level 2 Optimierungen, Best Practices & Architektur-Empfehlungen (z. B. Customer Lockbox, CMK für Storage/SQL, DDoS Protection Standard, LinkedIn-Integration, Lizenz-Upgrades wie Entra ID P2 für PIM) | **Geplant / Roadmap** |

---

## 12.2 Finding-Template für den Assessment-Bericht

Kopiere dieses Template pro Befund in deinen Prüfbericht:

```markdown
### [ID-001] Kurzer, prägnanter Titel des Findings

- **Schweregrad:** 🔴 Kritisch / 🟠 Hoch / 🟡 Mittel / 🔵 Niedrig
- **Domäne / Portal:** Microsoft Entra ID (`entra.microsoft.com`) / Azure Portal / Exchange Online / …
- **CIS-Referenz:** z. B. CIS M365 Foundations Benchmark – Control 5.2.2.2 (Level 1)
- **Betroffene Ressourcen / Scope:** Konkrete Namen, Subscriptions, Policies oder Anzahl betroffener Objekte

#### Beschreibung & Ist-Zustand
Sachliche Beschreibung der festgestellten Konfiguration (inkl. Evidenz: CLI-Ausgabe / Screenshot-Verweis).

#### Risiko & Auswirkung
Welcher konkrete Angriffsweg oder Schaden entsteht (z. B. Account Takeover, Lateral Movement, Datenabfluss, fehlende Forensik)?

#### Empfohlene Maßnahme (Soll-Zustand)
Konkrete, technisch umsetzbare Schritte zur Behebung (UI-Pfad und/oder CLI/IaC-Snippet) inkl. Hinweis auf eventuelle Betriebsauswirkungen / Rollout-Phase (z. B. zuerst „Report-only“).
```

---

## 12.3 Master-Checkliste (Abhakliste pro Assessment)

**Legende Rollen:**
- `GR` = Entra `Global Reader`
- `SR-E` = Entra `Security Reader`
- `SR-A` = Azure RBAC `Security Reader`
- `R-A` = Azure RBAC `Reader` *(optional – ohne `R-A` über Defender for Cloud Assessments prüfen)*

### A. Microsoft Entra ID *(Portal: `entra.microsoft.com` — 100 % Linux CLI via `az rest` / `m365`)*

| Status | ID | Prüfpunkt | CIS-Ref / Level | Rolle | UI / Linux CLI |
| :---: | :--- | :--- | :--- | :--- | :--- |
| [ ] | ENT-01 | Lizenzen, Domains & Hybrid-Sync-Status inventarisiert | Vorbereitung | `GR` | UI & `az rest` |
| [ ] | ENT-02 | Security Defaults vs. Conditional Access Status (`On` statt `Report-only`) | M365 5.2.2 / L1 | `GR` | UI & `az rest`/`m365` |
| [ ] | ENT-03 | MFA für alle Admins (ideal Phishing-resistant) & alle User inkl. Gäste erzwungen | M365 5.2.2 / L1 | `GR` | UI & `az rest`/`m365` |
| [ ] | ENT-04 | Legacy Authentication per CA blockiert | M365 5.2.2 / L1 | `GR` | UI & `az rest`/`m365` |
| [ ] | ENT-05 | CA Policy Exclusions geprüft (nur Break-Glass / dokumentierte Ausnahmen) | M365 5.2.2 / L1 | `GR` | UI & `az rest`/`m365` |
| [ ] | ENT-06 | Sign-in Risk & User Risk Policies aktiv (bei Entra ID P2) | M365 5.2.2 / L1 | `GR` | UI & `az rest`/`m365` |
| [ ] | ENT-07 | Global Administrators: 2–4 Konten, Cloud-only, dediziert, keine produktive Lizenz | M365 1.1 & 5.1 / L1 | `GR` | UI & `az rest` |
| [ ] | ENT-08 | 2 Break-Glass-Konten vorhanden, FIDO2-geschützt & überwacht | M365 5.1 / L1 | `GR` | UI & Interview |
| [ ] | ENT-09 | PIM aktiv für privilegierte Rollen (Eligible statt Active, MFA, Approval, Access Reviews) | M365 5.3 / L2 | `GR`/`SR-E` | UI & `az rest`/`m365` |
| [ ] | ENT-10 | Auth Methods Policy migriert, Number Matching aktiv, SMS/Voice deaktiviert | M365 5.2.3 / L1 | `GR` | UI & `az rest`/`m365` |
| [ ] | ENT-11 | MFA-Registrierungsquote (100 % Admins, alle aktiven Benutzer geprüft) | M365 5.2.3 / L1 | `GR` | UI & `az rest`/`m365` |
| [ ] | ENT-12 | Entra Password Protection (Smart Lockout & Custom Banned Passwords) | M365 5.2.3 / L1 | `GR` | UI & `az rest` |
| [ ] | ENT-13 | Entra Admin Center für Standard-Benutzer gesperrt (`Restrict access`) | M365 5.1.3 / L1 | `GR` | UI & `az rest` |
| [ ] | ENT-14 | App-Registrierungen durch Benutzer deaktiviert (`allowedToCreateApps = false`) | M365 5.1.3 / L1 | `GR` | UI & `az rest` |
| [ ] | ENT-15 | User Consent für Apps deaktiviert & Admin Consent Workflow aktiv | M365 5.1.5 / L1 | `GR` | UI & `az rest` |
| [ ] | ENT-16 | Gastzugriff auf „Most restrictive“ & Invite nur für berechtigte Rollen | M365 5.1.6 / L1 | `GR` | UI & `az rest` |
| [ ] | ENT-17 | High-Privilege Enterprise Apps & langlebige Client Secrets geprüft | M365 5.1.5 / L1 | `GR` | UI & `az rest` |
| [ ] | ENT-18 | Risky Users / Risky Sign-ins geprüft (Identity Protection) | M365 5.2.4 / L1 | `SR-E` | UI & `az rest`/`m365` |
| [ ] | ENT-19 | Entra Diagnostic Settings (Audit-/Sign-in-Logs → Log Analytics/Sentinel) | M365 5.2.6 / L1 | `GR`+`SR-A` | UI & `az rest` |

### B. Microsoft 365 Admin, Exchange Online & Defender for Office 365

| Status | ID | Prüfpunkt | CIS-Ref / Level | Portal | Linux CLI / Rolle |
| :---: | :--- | :--- | :--- | :--- | :--- |
| [ ] | M365-01 | Shared Mailboxes: Direkter Sign-In blockiert (`accountEnabled = false`) | M365 1.2 / L1 | M365 Admin | `az rest` (+ `pwsh`) / `GR` |
| [ ] | M365-02 | Public Microsoft 365 Groups auf unbeabsichtigte Freigaben geprüft | M365 1.2 / L2 | M365 Admin | `az rest` / `GR` |
| [ ] | M365-03 | Passwort-Ablauf auf „Never expire“ (mit MFA & Password Protection) | M365 1.3 / L1 | M365 Admin | `az rest` / `GR` |
| [ ] | M365-04 | Idle Session Timeout, Kalenderfreigabe, User-Owned Apps & Customer Lockbox | M365 1.3 / L1-L2 | M365 Admin | `az rest` + UI + `pwsh` / `GR` |
| [ ] | EXO-01 | SPF, DKIM & DMARC (`p=quarantine`/`p=reject`) für alle Domains geprüft | M365 2.1 / L1 | Defender + DNS | `az rest` + `dig` / `GR` |
| [ ] | EXO-02 | Modern Auth aktiv, SMTP AUTH tenant-weit deaktiviert, Reject Direct Send | M365 6.5 / L1 | EAC | Linux `pwsh` (EXO) / `GR` |
| [ ] | EXO-03 | Externe automatische Weiterleitung deaktiviert (Remote Domain + Outbound Spam) | M365 6.2 / L1 | EAC / Defender | Linux `pwsh` (EXO) / `GR` |
| [ ] | EXO-04 | Transport Rules auf Spam-Bypass (`SCL -1`) & Weiterleitungen geprüft | M365 6.2 / L1 | EAC | Linux `pwsh` (EXO) / `GR` |
| [ ] | EXO-05 | External Email Tagging, MailTips, OWA Storage Providers & Outlook Add-ins | M365 6.3-6.5 / L1 | EAC | Linux `pwsh` (EXO) / `GR` |
| [ ] | EXO-06 | Organization & Mailbox Auditing aktiv, kein unerlaubter Audit Bypass | M365 6.1 / L1 | EAC | Linux `pwsh` (EXO) / `GR` |
| [ ] | MDO-01 | Microsoft Secure Score geprüft & Top-Empfehlungen dokumentiert | M365 2.x / L1 | Defender | `az rest`/`m365` / `SR-E` |
| [ ] | MDO-02 | Anti-Phishing (Impersonation, Mailbox Intelligence, Spoof, Threshold ≥ 2) | M365 2.1 / L1 | Defender | Linux `pwsh` (EXO) / `SR-E` |
| [ ] | MDO-03 | Anti-Malware (Common Attachment Types Filter, ZAP, Admin Alerts) | M365 2.1 / L1 | Defender | Linux `pwsh` (EXO) / `SR-E` |
| [ ] | MDO-04 | Anti-Spam & Connection Filter (keine breiten IP- oder Domain-Allowlists!) | M365 2.1 / L1 | Defender | Linux `pwsh` (EXO) / `SR-E` |
| [ ] | MDO-05 | Safe Attachments (Mail + SPO/OneDrive/Teams) & Safe Links (Mail/Teams/Office) | M365 2.1 / L1 | Defender | Linux `pwsh` (EXO) / `SR-E` |

### C. SharePoint, OneDrive, Teams, Fabric, Purview & Intune

| Status | ID | Prüfpunkt | CIS-Ref / Level | Portal | Linux CLI / Rolle |
| :---: | :--- | :--- | :--- | :--- | :--- |
| [ ] | SPO-01 | Externes Sharing (kein „Anyone“), Domain-Einschränkung, Gäste dürfen nicht weiter teilen | M365 7.2 / L1 | SharePoint | `az rest`/`m365` + UI / `GR` |
| [ ] | SPO-02 | Default Sharing Link = Specific People / View, Ablaufdatum, Legacy Auth blockiert | M365 7.2-7.3 / L1 | SharePoint | `az rest`/`m365` + UI / `GR` |
| [ ] | SPO-03 | Unmanaged Devices & OneDrive Sync auf verwaltete/domänengejointe Geräte begrenzt | M365 7.2-7.3 / L2 | SharePoint | `az rest`/`m365` + UI / `GR` |
| [ ] | TMS-01 | Teams External Access: Unmanaged Teams Users & Skype Consumer blockiert, Federation eingeschränkt | M365 8.2 / L1 | Teams | Linux `pwsh` (Teams) / `GR` |
| [ ] | TMS-02 | Drittanbieter-Cloud-Speicher & Kanal-E-Mail-Integration deaktiviert | M365 8.1 / L1-L2 | Teams | Linux `pwsh` (Teams) / `GR` |
| [ ] | TMS-03 | Meeting Policies (Anonymous Join/Start, Lobby-Bypass, Externe Steuerung, Presenter) | M365 8.5 / L1-L2 | Teams | Linux `pwsh` (Teams) / `GR` |
| [ ] | TMS-04 | App Permission Policies (Drittanbieter-/Custom-Apps eingeschränkt) | M365 8.4 / L1 | Teams | Linux `pwsh` (Teams) / `GR` |
| [ ] | FAB-01 | Fabric / Power BI: „Publish to web“, Guest Access, External Sharing & Service Principals | M365 9.1 / L1 | Fabric | `curl` / ⚠️ Interview |
| [ ] | PRV-01 | Microsoft 365 Unified Audit Log aktiviert & Retention geprüft | M365 3.1 / L1 | Purview | `az rest` + Linux `pwsh` / `GR` |
| [ ] | PRV-02 | DLP-Policies & Sensitivity Labels aktiv geprüft | M365 3.2-3.3 / L1-L2 | Purview | `az rest` + Linux `pwsh` / `SR-E` |
| [ ] | INT-01 | Intune: „Mark devices with no compliance policy assigned as“ = **Not compliant** | M365 4.1 / L1 | Intune | `az rest`/`m365` / `GR` |
| [ ] | INT-02 | Enrollment Restrictions (BYOD) & Compliance Policies (BitLocker, OS, Firewall) | M365 4.2 / L1-L2 | Intune | `az rest`/`m365` / `GR` |

### D. Microsoft Azure Plattform *(Portal: `portal.azure.com`)*

| Status | ID | Prüfpunkt | CIS-Ref / Level | Rolle | Hinweis |
| :---: | :--- | :--- | :--- | :--- | :--- |
| [ ] | AZ-01 | Management Groups, Subscriptions & RBAC Owners (≤ 3, PIM, Gruppen statt User) | Azure 5.x / L1 | `SR-A` | Direkt per CLI/UI |
| [ ] | AZ-02 | Classic Administrators = 0 & keine Wildcard Custom Roles (`*`) | Azure 5.x / L1 | `SR-A` | Direkt per CLI/UI |
| [ ] | AZ-03 | Defender for Cloud Secure Score, Attack Paths & CIS Regulatory Compliance | Azure 8.1 / L1 | `SR-A` | Direkt per CLI/UI |
| [ ] | AZ-04 | Defender Plans (CSPM, Servers, Storage, SQL, Key Vault, Containers, ARM) | Azure 8.1 / L2 | `SR-A` | Direkt per CLI/UI |
| [ ] | AZ-05 | Defender Security Contacts (E-Mail, Severity High/Medium, Notify Owners) | Azure 8.1 / L1 | `SR-A` | Direkt per CLI/UI |
| [ ] | AZ-06 | Azure Policy Assignments, Compliance States & Exemptions geprüft | Azure 6.x / L1 | `SR-A` | Direkt per CLI/UI |
| [ ] | AZ-07 | Activity Log Export (Diagnostic Settings) & CIS Activity Log Alerts (NSG, Policy, SQL, Public IP) | Azure 6.1 / L1 | `SR-A` (+`R-A`) | Alerts mit `SR-A` |
| [ ] | AZ-08 | NSGs: Kein RDP (3389), SSH (22) oder `*` von `Internet` / `0.0.0.0/0` | Azure 7.1-7.4 / L1 | `R-A` *(oder `SR-A` via DfC)* | `securityresources` |
| [ ] | AZ-09 | Public IPs inventarisiert, Azure Bastion / JIT VM Access aktiv | Azure 7.6-7.9 / L1-L2 | `R-A` *(JIT: `SR-A`)* | `securityresources` |
| [ ] | AZ-10 | Network Watcher & VNet Flow Logs (≥ 90 Tage Retention) aktiv | Azure 7.5-7.7 / L1-L2 | `R-A` *(oder `SR-A` via DfC)* | `securityresources` |
| [ ] | AZ-11 | WAF (Prevention Mode), TLS ≥ 1.2, DDoS Standard & Private Endpoints | Azure 7.8+ / L1-L2 | `R-A` *(oder `SR-A` via DfC)* | `securityresources` |
| [ ] | AZ-12 | Storage Accounts: HTTPS only, TLS 1.2, kein Public Blob, kein Shared Key, Firewall/PE, Soft Delete | Azure 9.x / L1 | `R-A` *(oder `SR-A` via DfC)* | `securityresources` |
| [ ] | AZ-13 | Key Vault: Azure RBAC Model, Soft Delete, **Purge Protection**, Firewall/PE, Logging, Ablaufdaten | Azure 8.3 / L1 | `R-A` *(+KV Reader)* | `securityresources` |
| [ ] | AZ-14 | Datenbanken (SQL/PG/MySQL/Cosmos): Kein `0.0.0.0` Firewall, Entra-only Auth, TLS 1.2, Auditing, TDE | Azure DB / L1 | `R-A` *(oder `SR-A` via DfC)* | `securityresources` |
| [ ] | AZ-15 | VMs: Disk Encryption, Trusted Launch, Defender/EDR, Patching, Extensions, Managed Identities | Azure Compute / L1 | `R-A` *(oder `SR-A` via DfC)* | `securityresources` |
| [ ] | AZ-16 | App Services/Functions: HTTPS only, TLS 1.2, FTPS/No FTP, kein Remote Debug, CORS, Managed Identity | Azure Compute / L1 | `R-A` *(oder `SR-A` via DfC)* | `securityresources` |
| [ ] | AZ-17 | AKS & ACR: Entra RBAC, Local Accounts aus, Private Cluster/IPs, ACR Admin User aus | Azure Compute / L1 | `R-A` *(oder `SR-A` via DfC)* | `securityresources` |
| [ ] | AZ-18 | Analytics (Databricks/Synapse/Data Factory): Managed VNet, kein Public Access, Logging | Azure 2.x / L1-L2 | `R-A` *(oder `SR-A` via DfC)* | `securityresources` |
