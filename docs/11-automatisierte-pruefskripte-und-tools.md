# Kapitel 11: Automatisierung, Linux-CLI-Tools & Azure Resource Graph (KQL)

Manuelle UI-Klicks sind für tiefgehende Nachweise (Screenshots, Kontextprüfung) unverzichtbar – für eine **vollständige, fehlerfreie Abdeckung hunderter CIS-Kontrollen** über mehrere Subscriptions und M365-Workloads hinweg solltest du unter Linux **native CLI-Tools**, **Bash-Sammelskripte** und **Azure Resource Graph (KQL)** nutzen.

---

## 11.1 Empfohlene Open-Source-Tools unter Linux (`Global Reader` + `Security Reader`)

### A) 100 % Native Linux-CLI-Tools *(Python / Node.js – kein PowerShell nötig)*

| Tool | Fokus | CIS-Abdeckung | Benötigte Rollen | Output |
| :--- | :--- | :---: | :--- | :--- |
| **[Prowler](https://github.com/prowler-cloud/prowler)** *(Python)* | **Microsoft Azure** & **Microsoft 365** | ✅ CIS Azure & CIS M365 | Azure `Security Reader` + `Reader` / Entra `Global Reader` | HTML, CSV, JSON, OCSF |
| **[ScoutSuite](https://github.com/nccgroup/ScoutSuite)** *(Python)* | Microsoft Azure Infrastruktur (Multi-Subscription) | CIS Azure Mapping | Azure `Reader` + `Security Reader` | Interaktiver HTML-Report |
| **[ROADtools / roadrecon](https://github.com/dirkjanm/ROADtools)** *(Python)* | Tiefenanalyse Microsoft Entra ID (Rollen, Apps, CA, Geräte) | Security Posture | Entra `Global Reader` | Lokale Web-GUI & SQLite DB |
| **[CLI for Microsoft 365 (`m365`)](https://pnp.github.io/cli-microsoft365/)** *(Node.js)* | Entra ID, SharePoint, Teams, Purview & beliebige Graph-Requests (`m365 request`) | Basis für eigene Skripte | `Global Reader` + `Security Reader` | JSON / Text / CSV |

### B) Cross-Platform PowerShell-7-Tools *(laufen ebenfalls nativ unter Linux via `pwsh`)*

| Tool | Fokus | CIS-Abdeckung | Benötigte Rollen | Output |
| :--- | :--- | :---: | :--- | :--- |
| **[Maester](https://maester.dev)** | Entra ID, Conditional Access, M365 (Exchange, Teams, SPO), CISA & **CIS M365** | ✅ CIS M365 + EIDSCA | `Global Reader` + `Security Reader` | Interaktiver HTML-Report |
| **[Microsoft Zero Trust Assessment](https://microsoft.github.io/zerotrustassessment/)** | Offizielles Microsoft-Assessment (Identity, Devices, Network, Data) | Zero Trust + Best Practices | `Global Reader` + `Security Reader` (+ Azure `Reader`) | HTML-Report mit Priorisierung |
| **[CISA ScubaGear](https://github.com/cisagov/ScubaGear)** | M365 (Entra, Exchange, Defender, SPO, Teams) | CISA SCuBA Baseline | `Global Reader` *(ohne SPO-Admin: `-ProductNames aad,defender,exo,teams`)* | HTML + JSON |
| **[EntraFalcon](https://github.com/CompassSecurity/EntraFalcon)** | Entra ID Attack Paths, CA Exclusions, PIM, Apps, Azure RBAC | Security Posture | `Global Reader` *(ohne extra Graph Consent!)* | Interaktiver HTML-Report |

### Schnellstart auf Linux

#### 1. Prowler (Azure & M365 CIS-Scan – 100 % Linux CLI)
```bash
pipx install prowler

# Azure CIS Scan (nutzt aktive 'az login' Session!)
prowler azure --az-cli-auth --compliance cis_4.0_azure

# M365 CIS Scan
prowler m365 --az-cli-auth --compliance cis_4.0_m365
```

#### 2. ScoutSuite (Azure Multi-Subscription – 100 % Linux CLI)
```bash
pipx install scoutsuite
scout azure --cli
```

#### 3. ROADrecon (Entra ID Deep-Dive – 100 % Linux CLI)
```bash
pipx install roadrecon
roadrecon auth --device-code --tenant "<TENANT_ID>"
roadrecon gather
roadrecon gui
```

#### 4. Maester (CIS M365 & Entra ID – unter Linux via `pwsh`)
```bash
pwsh -NoLogo -Command '
  Install-Module Maester -Scope CurrentUser -Force
  mkdir -Force maester-tests | Out-Null; cd maester-tests
  Install-MaesterTests
  Connect-Maester -Service All
  Invoke-Maester -OutputHtmlFile "./Maester-Report.html"
'
```

---

## 11.2 Mitgelieferte Read-Only-Sammelskripte in diesem Repository

Im Ordner [`scripts/`](../scripts/) liegen vier sofort ausführbare, **100 % schreibgeschützte (Read-Only)** Linux-Werkzeuge:

1. **[`scripts/audit-azure-security-reader.sh`](../scripts/audit-azure-security-reader.sh)** *(100 % Linux Bash + Azure CLI)*
   - Erkennt automatisch, ob du nur Azure `Security Reader` oder zusätzlich Azure `Reader` besitzt.
   - Exportiert für alle sichtbaren Subscriptions: RBAC-Rollen, Classic Admins, Custom Roles, Defender for Cloud Secure Score, Defender Plans, Security Contacts, CIS Regulatory Compliance, Unhealthy Assessments, Policy States, Log Analytics Workspaces und Activity Log Alerts – plus (falls `Reader` vorhanden) Storage, Key Vault, NSGs, Public IPs, SQL, VMs, App Services, AKS & ACR.

   ```bash
   az login --tenant "<TENANT_ID>"
   ./scripts/audit-azure-security-reader.sh
   ```

2. **[`scripts/audit-m365-entra-linux.sh`](../scripts/audit-m365-entra-linux.sh)** *(100 % Linux Bash + `az rest` / `m365` + `jq` + `dig`)*
   - Sammelt rein über Linux-CLI ohne PowerShell: Tenant-Infos, Lizenzen, Domains, **DNS-Prüfung (SPF/DMARC/DKIM per `dig`)**, Entra ID (Security Defaults, CA Policies, Named Locations, Rollen, Global Admins, PIM, Auth Methods, MFA-Registrierung, Authorization Policy, Consent, Cross-Tenant, Gäste, App Secrets, Risky Users, Diagnostic Settings), M365 Public Groups, Idle Session Timeout, Defender Secure Score, SharePoint Tenant Settings, Intune Compliance & Purview Sensitivity Labels.
   - Optionaler Switch `--with-pwsh` hängt automatisch Exchange Online, Defender for O365 & Teams (via Linux-`pwsh`) an!

   ```bash
   # Variante A: mit Azure CLI ('az login --tenant <TID> --allow-no-subscriptions')
   ./scripts/audit-m365-entra-linux.sh

   # Variante B: mit CLI for Microsoft 365 (empfohlen, falls az rest bei Graph-Scopes 403 liefert)
   m365 login --authType deviceCode --tenant "<TENANT_ID>"
   ./scripts/audit-m365-entra-linux.sh --tool m365

   # Variante C: inkl. Exchange Online, Defender O365 & Teams via Linux-pwsh
   ./scripts/audit-m365-entra-linux.sh --tool m365 --with-pwsh --tenant "<TENANT_ID>" --upn "auditor@kunde.de"
   ```

3. **[`scripts/audit-m365-entra-reader.ps1`](../scripts/audit-m365-entra-reader.ps1)** *(PowerShell 7 – läuft nativ unter Linux via `pwsh`)*
   - Vollständiger Collector inkl. **Exchange Online**, **Defender for Office 365**, **Microsoft Teams** und optional **Purview (`-IncludePurview`)**; unterstützt `-SkipGraph` (wenn Graph bereits über `audit-m365-entra-linux.sh` eingesammelt wurde) sowie `-UseDeviceAuth` für Headless-Linux!

   ```bash
   pwsh ./scripts/audit-m365-entra-reader.ps1 -TenantId "<TENANT_ID>" -UserPrincipalName "auditor@kunde.de" -UseDeviceAuth
   ```

4. **[`scripts/kql-resource-graph-queries.kql`](../scripts/kql-resource-graph-queries.kql)** *(Azure Resource Graph KQL)*
   - Fertige KQL-Abfragen für `az graph query` (Linux CLI) oder den Resource Graph Explorer im Azure Portal – sauber getrennt nach `Security Reader` (`securityresources` / `policyresources`) und `Reader` (`resources`).

---

## 11.3 Azure Resource Graph (KQL) – Schnell-Spickzettel für Linux CLI

Alle Abfragen lassen sich direkt in der Linux-Bash über `az graph query -q "..."` ausführen:

### A) Funktioniert mit reinem Azure `Security Reader`

```bash
# 1. Secure Score aller Subscriptions im Überblick
az graph query -q "
securityresources
| where type == 'microsoft.security/securescores'
| project SubscriptionId=subscriptionId,
          CurrentScore=round(todouble(properties.score.current), 2),
          MaxScore=todouble(properties.score.max),
          Percentage=round(todouble(properties.score.percentage) * 100, 1)
| order by Percentage asc
" -o table

# 2. Top Unhealthy Defender Recommendations nach Schweregrad gruppiert
az graph query -q "
securityresources
| where type == 'microsoft.security/assessments'
| where properties.status.code == 'Unhealthy'
| summarize AffectedResources=count() by
    Assessment=tostring(properties.displayName),
    Severity=tostring(properties.metadata.severity)
| order by Severity desc, AffectedResources desc
" --first 50 -o table

# 3. CIS Regulatory Compliance fehlgeschlagene Kontrollen
az graph query -q "
securityresources
| where type == 'microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols'
| where id has 'CIS' and properties.state == 'Failed'
| project SubscriptionId=subscriptionId,
          Control=name,
          Description=tostring(properties.description),
          FailedResources=toint(properties.failedResources)
| order by FailedResources desc
" --first 100 -o table
```

### B) Benötigt zusätzlich Azure `Reader`

```bash
# 4. Unsichere Storage Accounts über alle Subscriptions
az graph query -q "
resources
| where type =~ 'microsoft.storage/storageaccounts'
| where properties.allowBlobPublicAccess != false
     or properties.supportsHttpsTrafficOnly != true
     or properties.minimumTlsVersion != 'TLS1_2'
     or properties.allowSharedKeyAccess != false
| project SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Name=name,
          PublicBlob=properties.allowBlobPublicAccess,
          HTTPSOnly=properties.supportsHttpsTrafficOnly,
          MinTLS=properties.minimumTlsVersion,
          SharedKey=properties.allowSharedKeyAccess,
          NetDefault=properties.networkAcls.defaultAction
" -o table

# 5. Key Vaults ohne Purge Protection oder ohne Azure RBAC
az graph query -q "
resources
| where type =~ 'microsoft.keyvault/vaults'
| where properties.enablePurgeProtection != true or properties.enableRbacAuthorization != true
| project SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Name=name,
          PurgeProtection=properties.enablePurgeProtection,
          RBAC=properties.enableRbacAuthorization,
          PublicNet=properties.publicNetworkAccess
" -o table
```
