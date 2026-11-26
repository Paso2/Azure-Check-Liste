# Kapitel 6: Compliance, Datenschutz & Endgeräte – Microsoft Purview & Microsoft Intune

**CIS-Referenz:** CIS Microsoft 365 Foundations Benchmark – *Section 3 (Microsoft Purview)* & *Section 4 (Microsoft Intune)*  
**Primäre Portale:**
- **Microsoft Purview Portal:** `https://purview.microsoft.com`
- **Microsoft Intune Admin Center:** `https://intune.microsoft.com`

**Erforderliche Rollen & Linux-CLI-Status:**
- **Microsoft Intune:** **100 % nativ unter Linux via `az rest` / `m365` + `jq`** mit `Global Reader` ✅ *(kein PowerShell erforderlich!)*.
- **Microsoft Purview:** Sensitivity Labels & Audit-Events lassen sich via **Linux CLI (`az rest` / `m365` auf Microsoft Graph)** abfragen; für **DLP-Policies, Unified-Audit-Schalter & Audit-Retention-Policies** existiert keine öffentliche Graph-REST-API → Abfrage unter Linux via **`pwsh` (`Connect-ExchangeOnline` / `Connect-IPPSSession`)** oder über die Purview-UI. *(Hinweis: Einzelne Purview-Bereiche erfordern ggf. explizite Purview-Rollengruppen zusätzlich zu `Security Reader` + `Global Reader`.)*

---

## 6.1 Microsoft Purview – Unified Audit Log, DLP & Sensitivity Labels (CIS Section 3)

### Erklärung & Risiko
Ohne aktiviertes **Microsoft 365 Unified Audit Log** existiert im Sicherheitsvorfall keinerlei Nachvollziehbarkeit, welche E-Mails gelesen, welche SharePoint-Dateien heruntergeladen oder welche Admin-Änderungen vorgenommen wurden. **DLP-Richtlinien** und **Sensitivity Labels** bilden die datenzentrierte Schutzschicht gegen Datenverlust und Fehlfreigaben.

### Soll-Zustand (CIS 3.1.x – 3.3.x / L1 & L2)
- **Microsoft 365 Unified Audit Log:** Aktiviert (`UnifiedAuditLogIngestionEnabled = true`) *(L1 – zwingend!)*.
- **Audit Retention Policy:** Standard-Aufbewahrung (180 Tage) aktiv; bei E5/Purview Audit (Premium) mind. **1 Jahr** *(L1/L2)*.
- **Data Loss Prevention (DLP):** Aktive DLP-Richtlinien (Modus `Enable`, nicht nur `TestWithNotifications`!) mindestens für **Exchange, SharePoint, OneDrive & Teams** *(L1/L2)*.
- **Sensitivity Labels:** Definiert, publiziert und produktiv genutzt (idealerweise Default-/Pflicht-Labeling & Verschlüsselung für „Vertraulich“) *(L2)*.

### Prüfung via UI (Microsoft Purview Portal – `https://purview.microsoft.com`)
1. **Audit:** `Purview Portal` → *Solutions → Audit* → prüfen, ob oben ein Banner „Start recording user and admin activity“ erscheint (falls ja = **NICHT aktiviert → Kritisches Finding!**). Unter *Audit retention policies* Aufbewahrungsfristen prüfen.
2. **DLP:** *Solutions → Data Loss Prevention → Policies* → Status (`On` vs. `Simulation`) & abgedeckte Workloads prüfen.
3. **Information Protection:** *Solutions → Information Protection → Labels* & *Label policies*.
4. **Data Lifecycle Management:** *Solutions → Data Lifecycle Management → Retention policies*.

### Prüfung via Linux CLI

```bash
# 1. Sensitivity Labels nativ via Linux CLI (Microsoft Graph REST!)
#    (Bei 403 mit az rest -> 'm365 request --url ... --output json' nutzen)
az rest --method GET \
  --url "https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels" -o json \
| jq -r '
  ["Name","Description","Active"],
  (.value[] | [.name, (.description // "-"), (.isActive | tostring)]) | @tsv
' | column -t -s $'\t'

# 2. Prüfen, ob aktuelle Audit-Logs in Entra / M365 ankommen (Linux CLI)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$top=5" \
  --query "value[].{Time:activityDateTime, Activity:activityDisplayName, Category:category}" -o table
```

```bash
# 3. Unified Audit Log Status, DLP Policies & Audit Retention Policies
#    [Microsoft-Limit: keine Graph-REST-API -> Aufruf direkt aus Linux-Bash über pwsh:]
pwsh -NoLogo -Command '
  # Unified Audit Log Status (Exchange Online)
  Connect-ExchangeOnline -Device -UserPrincipalName "auditor@kunde.de" -ShowBanner:$false
  Write-Host "`n=== Unified Audit Log Config ==="
  Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled, AdminAuditLogEnabled, AdminAuditLogAgeLimit | Format-List
  Disconnect-ExchangeOnline -Confirm:$false

  # Purview DLP, Labels & Audit Retention (Security & Compliance)
  Connect-IPPSSession -Device -UserPrincipalName "auditor@kunde.de" -ShowBanner:$false
  Write-Host "=== DLP Policies ==="
  Get-DlpCompliancePolicy | Select-Object Name, Enabled, Mode, ExchangeLocation, SharePointLocation, OneDriveLocation, TeamsLocation | Format-Table -AutoSize
  Write-Host "=== Sensitivity Labels & Policies ==="
  Get-Label | Select-Object DisplayName, Name, Disabled, Priority | Format-Table -AutoSize
  Get-LabelPolicy | Select-Object Name, Enabled, Mode | Format-Table -AutoSize
  Write-Host "=== Audit Retention Policies ==="
  Get-UnifiedAuditLogRetentionPolicy | Select-Object Name, Priority, RecordTypes, RetentionDuration, Enabled | Format-Table -AutoSize
  Disconnect-ExchangeOnline -Confirm:$false
'
```

---

## 6.2 Microsoft Intune – Endgeräte-Vertrauen & Compliance (CIS Section 4)

### Erklärung & Risiko
Conditional Access kann nur dann wirksam „nur vertrauenswürdige, konforme Geräte“ erzwingen, wenn Intune **Geräte ohne zugewiesene Compliance-Richtlinie standardmäßig als „Non-compliant“** markiert und das Einschreiben privater (BYOD) oder manipulierter Endgeräte kontrolliert wird.

### Soll-Zustand (CIS 4.1 – 4.2 & Best Practice / L1 & L2)
- **Mark devices with no compliance policy assigned as:** **Not compliant** (`secureByDefault == true`) *(CIS L1 – kritische Standard-Falle: Default ist „Compliant“!)*.
- **Device Enrollment Restrictions:** Persönliche (BYOD) Geräte für Windows/macOS (und je nach Strategie iOS/Android) im Enrollment blockiert *(L1/L2)*.
- **Device Compliance Policies:** Für alle genutzten Plattformen aktiv (BitLocker/FileVault, Firewall, Defender for Endpoint, OS-Mindestversion, Jailbreak-/Root-Erkennung).
- **App Protection Policies (MAM):** Für BYOD-Zugriffe auf M365-Apps konfiguriert.
- **Entra Device Settings (Cross-Check):**
  - *Require MFA to register or join devices* = **Yes** *(CIS 5.1.4.x / L1)*.
  - *Maximum number of devices per user* begrenzt *(L2)*.

### Prüfung via UI (Intune Admin Center – `https://intune.microsoft.com`)
1. **Compliance Policy Settings (CIS-Pflichtcheck!):** `Intune Admin Center` → *Devices → Compliance → Compliance policy settings* → **Mark devices with no compliance policy assigned as = Not compliant**.
2. **Compliance Policies:** *Devices → Compliance → Policies*.
3. **Enrollment Restrictions:** *Devices → Enroll devices → Enrollment device platform restrictions* → Spalte **Personally owned** prüfen.
4. **App Protection Policies:** *Apps → Protection → App protection policies*.
5. **Entra Device Settings:** `Entra Admin Center` (`entra.microsoft.com`) → *Identity → Devices → Overview → Device settings*.

### Prüfung via Linux CLI (`az rest` / `m365` + `jq` – 100 % nativ unter Linux!)

```bash
# Hinweis: Falls az rest bei /deviceManagement/* ein 403 liefert, einfach 'm365 request --url ... --output json' verwenden!

# 1. CIS-Pflichtcheck: "Mark devices with no compliance policy assigned as"
#    secureByDefault == true  => "Not compliant" (CIS SOLL!)
#    secureByDefault == false => "Compliant"     (FINDING!)
az rest --method GET \
  --url "https://graph.microsoft.com/beta/deviceManagement/settings" \
  --query "{SecureByDefault_NotCompliant:secureByDefault, DeviceComplianceCheckinThresholdDays:deviceComplianceCheckinThresholdDays}" -o table

# 2. Alle Intune Device Compliance Policies auflisten
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies" \
  --query "value[].{Name:displayName, Platform:\"@odata.type\", LastModified:lastModifiedDateTime}" -o table

# 3. Compliance-Status aller verwalteten Geräte zusammenfassen (mit jq!)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?\$select=deviceName,operatingSystem,complianceState&\$top=999" -o json \
| jq '.value | group_by(.complianceState) | map({state: .[0].complianceState, count: length})'

# 4. Device Enrollment Platform Restrictions prüfen (BYOD erlauben vs. blockieren)
az rest --method GET \
  --url "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations" -o json \
| jq '.value[] | select(."@odata.type" | contains("PlatformRestrictions")) | {
    name: .displayName,
    priority: .priority,
    windows: .windowsRestriction,
    macOS: .macOSRestriction,
    ios: .iosRestriction,
    android: .androidRestriction
  }'

# 5. Entra ID Device Registration Policy prüfen (MFA für Device Join & max. Geräte/User)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/policies/deviceRegistrationPolicy" -o json \
| jq '{
    multiFactorAuthConfiguration: .multiFactorAuthConfiguration,
    userDeviceQuota: .userDeviceQuota,
    azureADJoin: .azureADJoin.appliesTo,
    azureADRegistration: .azureADRegistration.appliesTo
  }'
```
