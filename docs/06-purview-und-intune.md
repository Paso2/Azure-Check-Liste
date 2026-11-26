# Kapitel 6: Compliance, Datenschutz & Endgeräte – Microsoft Purview & Microsoft Intune

**CIS-Referenz:** CIS Microsoft 365 Foundations Benchmark – *Section 3 (Microsoft Purview)* & *Section 4 (Microsoft Intune)*  
**Primäre Portale:**
- **Microsoft Purview Portal:** `https://purview.microsoft.com`
- **Microsoft Intune Admin Center:** `https://intune.microsoft.com`

**Erforderliche Rollen & Grenzen:**
- **Microsoft Purview:** Entra `Security Reader` + `Global Reader` geben Read-Only-Zugriff auf viele Compliance-Einstellungen (insb. via `Connect-IPPSSession` für DLP/Labels/Audit). **Achtung:** Einige Bereiche im Purview-Portal (z. B. *Content Search*, *eDiscovery*, *Audit Search* oder spezifische Purview-Rollen) setzen explizite **Purview-Rollengruppen** (z. B. *View-Only Audit Logs* oder *Compliance Data Administrator*) voraus.
- **Microsoft Intune:** `Global Reader` kann im Intune Admin Center und über Microsoft Graph alle Compliance-, Konfigurations- und Enrollment-Richtlinien lesen ✅.

---

## 6.1 Microsoft Purview – Unified Audit Log, DLP & Sensitivity Labels (CIS Section 3)

### Erklärung & Risiko
Ohne aktiviertes **Microsoft 365 Unified Audit Log** existiert im Sicherheitsvorfall keinerlei Nachvollziehbarkeit, welche E-Mails gelesen, welche SharePoint-Dateien heruntergeladen oder welche Admin-Änderungen vorgenommen wurden. **DLP-Richtlinien** und **Sensitivity Labels** bilden die datenzentrierte Schutzschicht gegen Datenverlust und Fehlfreigaben.

### Soll-Zustand (CIS 3.1.x – 3.3.x / L1 & L2)
- **Microsoft 365 Unified Audit Log:** Aktiviert (`UnifiedAuditLogIngestionEnabled = $true`) *(L1 – zwingend!)*.
- **Audit Retention Policy:** Standard-Aufbewahrung (180 Tage) aktiv; bei E5/Purview Audit (Premium) mind. **1 Jahr** (besser länger nach Compliance-Vorgaben) für kritische Dienste *(L1/L2)*.
- **Data Loss Prevention (DLP):** Aktive DLP-Richtlinien (im Modus `Enable`, nicht nur `TestWithNotifications`!) mindestens für **Exchange Online, SharePoint Online, OneDrive & Teams** *(L1/L2)*.
- **Sensitivity Labels (Information Protection):** Definiert, veröffentlicht und idealerweise mit Standard-Labeling / Pflicht-Labeling sowie Verschlüsselung für „Vertraulich / Streng Vertraulich“ konfiguriert *(L2)*.
- **Defender for Cloud Apps / Purview Audit Anbindung:** Aktiv, damit M365-Aktivitäten zentral korreliert werden *(L2)*.

### Prüfung via UI (Microsoft Purview Portal – `https://purview.microsoft.com`)
1. **Audit:** `Purview Portal` → *Solutions → Audit* → prüfen, ob oben ein Banner „Start recording user and admin activity“ erscheint (falls ja = **NICHT aktiviert → Kritisches Finding!**). Unter *Audit retention policies* Aufbewahrungsfristen prüfen.
2. **DLP:** *Solutions → Data Loss Prevention → Policies* → aktive Policies, Status (`On` vs. `Simulation`), abgedeckte Workloads (Exchange, SharePoint, OneDrive, Teams, Devices) prüfen.
3. **Information Protection (Sensitivity Labels):** *Solutions → Information Protection → Labels* & *Label policies* (prüfen, ob Labels publiziert und produktiv genutzt werden).
4. **Data Lifecycle Management:** *Solutions → Data Lifecycle Management → Retention policies* (Schutz vor versehentlichem/böswilligem Löschen).

### Prüfung via CLI / PowerShell (Exchange Online & Security & Compliance PowerShell)

```powershell
# 1. Unified Audit Log Status prüfen (Exchange Online PowerShell)
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled, AdminAuditLogEnabled, AdminAuditLogAgeLimit | Format-List

# 2. Security & Compliance PowerShell (Purview) verbinden
Connect-IPPSSession -UserPrincipalName "auditor@kunde.de"

# 3. DLP Policies & Status prüfen
Get-DlpCompliancePolicy | Select-Object Name, Enabled, Mode, ExchangeLocation, SharePointLocation, OneDriveLocation, TeamsLocation | Format-Table -AutoSize

# 4. Sensitivity Labels & Label Policies prüfen
Get-Label | Select-Object DisplayName, Name, Disabled, Priority, ContentType | Format-Table -AutoSize
Get-LabelPolicy | Select-Object Name, Enabled, Mode, Labels | Format-Table -AutoSize

# 5. Audit Retention Policies prüfen (bei Audit Premium / E5)
Get-UnifiedAuditLogRetentionPolicy | Select-Object Name, Priority, RecordTypes, RetentionDuration, Enabled | Format-Table -AutoSize
```

---

## 6.2 Microsoft Intune – Endgeräte-Vertrauen & Compliance (CIS Section 4)

### Erklärung & Risiko
Conditional Access kann nur dann wirksam „nur vertrauenswürdige, konforme Geräte“ erzwingen, wenn Intune **Geräte ohne zugewiesene Compliance-Richtlinie standardmäßig als „Non-compliant“** markiert und das Einschreiben privater (BYOD) oder manipulierter Endgeräte kontrolliert wird.

### Soll-Zustand (CIS 4.1 – 4.2 & Best Practice / L1 & L2)
- **Mark devices with no compliance policy assigned as:** **Not compliant** *(CIS L1 – kritische Standard-Falle: Default ist „Compliant“!)*.
- **Device Enrollment Restrictions:** Persönliche (BYOD) Geräte für Windows/macOS (und je nach Strategie iOS/Android) im Enrollment blockiert, um unkontrollierte Privatgeräte aus dem Unternehmensnetz fernzuhalten *(L1/L2)*.
- **Device Compliance Policies:** Für alle genutzten Plattformen (Windows, macOS, iOS, Android) aktiv:
  - Festplattenverschlüsselung (BitLocker / FileVault) gefordert.
  - Firewall & Antivirus (Defender for Endpoint) aktiv & gesund.
  - OS-Mindestversion definiert (keine EOL-Betriebssysteme!).
  - Jailbreak-/Root-Erkennung aktiviert (Mobile).
- **App Protection Policies (MAM):** Für BYOD-Zugriffe auf M365-Apps (Outlook, Teams, OneDrive) konfiguriert (PIN, kein Copy/Paste in private Apps, verschlüsselte App-Daten).
- **Entra Device Settings (Cross-Check in Entra Portal):**
  - *Require Multi-Factor Authentication to register or join devices with Microsoft Entra* = **Yes** *(CIS 5.1.4.x / L1)*.
  - *Maximum number of devices per user* begrenzt (z. B. 5–20 statt unbegrenzt) *(L2)*.
  - *Local administrator settings on Microsoft Entra joined devices* restriktiv (nicht jeder Standard-User als lokaler Admin!).

### Prüfung via UI (Intune Admin Center – `https://intune.microsoft.com`)
1. **Compliance Policy Settings (CIS-Pflichtcheck!):** `Intune Admin Center` → *Devices → Compliance → Compliance policy settings* → prüfen: **Mark devices with no compliance policy assigned as = Not compliant**.
2. **Compliance Policies:** *Devices → Compliance → Policies* → Plattform-Abdeckung und Einstellungen prüfen.
3. **Enrollment Restrictions:** *Devices → Enroll devices → Enrollment device platform restrictions* → Spalte **Personally owned** (Allow vs. Block) pro Plattform prüfen.
4. **App Protection Policies:** *Apps → Protection → App protection policies*.
5. **Entra Device Settings:** `Entra Admin Center` (`entra.microsoft.com`) → *Identity → Devices → Overview → Device settings*.

### Prüfung via CLI / PowerShell (Microsoft Graph – funktioniert mit `Global Reader`!)

```powershell
# 1. Intune Device Compliance Policies auflisten
Get-MgDeviceManagementDeviceCompliancePolicy -All |
    Select-Object DisplayName, Id, LastModifiedDateTime, '@odata.type' | Format-Table -AutoSize

# 2. Compliance Settings: "Mark devices with no compliance policy assigned as" (via Graph Beta / Settings)
# SecureByDefault = $true bedeutet "Not compliant" (CIS SOLL!)
Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/settings" |
    Select-Object -ExpandProperty secureByDefault

# 3. Übersicht verwalteter Geräte & Compliance-Zustand
Get-MgDeviceManagementManagedDevice -All | Group-Object ComplianceState | Select-Object Name, Count

# 4. Enrollment Platform Restrictions prüfen
Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations" |
    Select-Object -ExpandProperty value |
    Select-Object displayName, '@odata.type', priority | Format-Table -AutoSize

# 5. Entra ID Device Registration Policy prüfen (MFA für Device Join)
Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/deviceRegistrationPolicy" |
    ConvertTo-Json -Depth 5
```
