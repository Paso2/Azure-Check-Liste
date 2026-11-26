# Kapitel 11: Automatisierung, Open-Source-Assessment-Tools & Azure Resource Graph (KQL)

Manuelle UI-Klicks sind für tiefgehende Nachweise (Screenshots, Kontextprüfung) unverzichtbar – für eine **vollständige, fehlerfreie Abdeckung hunderter CIS-Kontrollen** über mehrere Subscriptions und M365-Workloads hinweg solltest du jedoch **automatisierte Read-Only-Tools** und **Sammelskripte** nutzen.

---

## 11.1 Empfohlene Open-Source-Tools für `Global Reader` + `Security Reader`

| Tool | Fokus | CIS-Abdeckung | Benötigte Rollen | Output |
| :--- | :--- | :---: | :--- | :--- |
| **[Maester](https://maester.dev)** | Entra ID, Conditional Access, M365 (Exchange, Teams, SPO), CISA & **CIS M365** | ✅ CIS M365 + EIDSCA | `Global Reader` + `Security Reader` *(Graph Read-Only Scopes)* | Interaktiver HTML-Report |
| **[Prowler](https://github.com/prowler-cloud/prowler)** | **Microsoft Azure** & **Microsoft 365** | ✅ CIS Azure & CIS M365 | Azure `Security Reader` + `Reader` / Entra `Global Reader` | HTML, CSV, JSON, OCSF |
| **[Microsoft Zero Trust Assessment](https://microsoft.github.io/zerotrustassessment/)** | Offizielles Microsoft-Assessment (Identity, Devices, Network, Data) | Zero Trust + Best Practices | `Global Reader` + `Security Reader` (+ Azure `Reader`) | HTML-Report mit Priorisierung |
| **[CISA ScubaGear](https://github.com/cisagov/ScubaGear)** | M365 (Entra, Exchange, Defender, SPO, Teams, Power Platform) | CISA SCuBA Baseline *(hohe Überschneidung mit CIS M365)* | `Global Reader` *(für SPO/Power Platform ggf. eingeschränkt)* | HTML + JSON |
| **[EntraFalcon](https://github.com/CompassSecurity/EntraFalcon)** | Tiefenanalyse Entra ID (Attack Paths, CA Exclusions, PIM, Apps, Azure RBAC) | Security Posture / Red-Team-Perspektive | `Global Reader` *(ohne extra Graph Consent!)* | Interaktiver HTML-Report |
| **[ScoutSuite](https://github.com/nccgroup/ScoutSuite)** | Microsoft Azure Infrastruktur (Multi-Subscription) | CIS Azure Mapping | Azure `Reader` + `Security Reader` | Interaktiver HTML-Report |

### Schnellstart der wichtigsten Tools

#### 1. Maester (Entra ID & M365 – extrem beliebt bei CIS-Assessments)
```powershell
Install-Module Maester -Scope CurrentUser
mkdir maester-tests && cd maester-tests
Install-MaesterTests
Connect-Maester -Service All
Invoke-Maester -OutputHtmlFile ".\Maester-Report.html"
```

#### 2. Prowler (Azure & M365 gegen CIS Benchmarks)
```bash
# Installation via pip / pipx
pipx install prowler

# Azure CIS Scan (nutzt bestehende 'az login' Session!)
prowler azure --az-cli-auth --compliance cis_4.0_azure

# M365 CIS Scan
prowler m365 --az-cli-auth --compliance cis_4.0_m365
```

#### 3. Microsoft Zero Trust Assessment
```powershell
Install-Module ZeroTrustAssessment -Scope CurrentUser
Connect-ZtAssessment
Invoke-ZtAssessment -Path ".\ZeroTrust-Report"
```

#### 4. CISA ScubaGear (M365)
```powershell
Install-Module -Name ScubaGear -Scope CurrentUser
Initialize-SCuBA
Invoke-SCuBA -ProductNames aad,defender,exo,teams
# Hinweis: 'sharepoint' erfordert SharePoint Admin; ohne SharePoint Admin oben weglassen und per UI/Graph prüfen!
```

---

## 11.2 Mitgelieferte Read-Only-Sammelskripte in diesem Repository

In diesem Repository findest du drei sofort einsetzbare, **100 % schreibgeschützte (Read-Only)** Hilfsmittel im Ordner [`scripts/`](../scripts/):

1. **[`scripts/audit-azure-security-reader.sh`](../scripts/audit-azure-security-reader.sh)** *(Bash + Azure CLI)*
   - Erkennt automatisch, ob du nur `Security Reader` oder zusätzlich Azure `Reader` besitzt.
   - Exportiert für alle sichtbaren Subscriptions: RBAC-Rollen (`Owner`/`Contributor`/`UAA`), Classic Admins, Custom Roles, Defender for Cloud Secure Score, Defender Plans, Security Contacts, Regulatory Compliance (CIS), Unhealthy Assessments, Policy States, Log Analytics Workspaces und Activity Log Alerts.
   - Falls Azure `Reader` vorhanden ist, zieht es zusätzlich: Storage Accounts, Key Vaults, NSGs (riskante Internet-Regeln), Public IPs, SQL Server, VMs, App Services, AKS & ACR.
   - Alle Ergebnisse werden strukturiert als JSON/TXT im Ordner `azure-audit-output_<DATUM>/` abgelegt.

   ```bash
   az login --tenant "<TENANT_ID>"
   chmod +x scripts/audit-azure-security-reader.sh
   ./scripts/audit-azure-security-reader.sh
   ```

2. **[`scripts/audit-m365-entra-reader.ps1`](../scripts/audit-m365-entra-reader.ps1)** *(PowerShell 7)*
   - Verbindet sich im reinen Read-Only-Modus zu **Microsoft Graph**, **Exchange Online** und **Microsoft Teams** (optional Purview via `-IncludePurview`).
   - Sammelt automatisiert alle relevanten CIS-M365-Evidenzen (Lizenzen, Domains, Security Defaults, CA Policies, Global Admins, MFA-Registrierung, Authorization Policy, High-Priv Apps, Shared Mailboxes mit aktivem Login, Exchange Org/SMTP/Forwarding/Transport Rules/DKIM/Defender Policies, Teams Federation/Meetings, Intune Compliance Settings & SharePoint Graph Settings).
   - Exportiert alles sauber nach `m365-audit-output_<DATUM>/`.

   ```powershell
   pwsh ./scripts/audit-m365-entra-reader.ps1 -TenantId "<TENANT_ID>" -UserPrincipalName "auditor@kunde.de"
   ```

3. **[`scripts/kql-resource-graph-queries.kql`](../scripts/kql-resource-graph-queries.kql)** *(Azure Resource Graph KQL)*
   - Sammlung fertiger KQL-Abfragen für das **Azure Portal (Resource Graph Explorer)** oder `az graph query` – strikt getrennt in:
     - **Teil A:** Abfragen, die **mit reinem Azure `Security Reader`** funktionieren (`securityresources` & `policyresources`)
     - **Teil B:** Abfragen, die **zusätzlich Azure `Reader`** benötigen (`resources`)

---

## 11.3 Azure Resource Graph (KQL) – Schnell-Spickzettel

Über **`Azure Portal` → Suche nach *Resource Graph Explorer*** (oder per CLI `az graph query -q "..."`) lassen sich hunderte Subscriptions in unter 2 Sekunden abfragen:

### A) Funktioniert mit reinem Azure `Security Reader`

```kql
// 1. Secure Score aller Subscriptions im Überblick
securityresources
| where type == "microsoft.security/securescores"
| project SubscriptionId=subscriptionId,
          CurrentScore=round(todouble(properties.score.current), 2),
          MaxScore=todouble(properties.score.max),
          Percentage=round(todouble(properties.score.percentage) * 100, 1)
| order by Percentage asc
```

```kql
// 2. Top Unhealthy Defender Recommendations nach Schweregrad gruppiert
securityresources
| where type == "microsoft.security/assessments"
| where properties.status.code == "Unhealthy"
| summarize AffectedResources=count() by
    Assessment=tostring(properties.displayName),
    Severity=tostring(properties.metadata.severity)
| order by Severity desc, AffectedResources desc
```

```kql
// 3. CIS Regulatory Compliance fehlgeschlagene Kontrollen
securityresources
| where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols"
| where id has "CIS" and properties.state == "Failed"
| project SubscriptionId=subscriptionId,
          Control=name,
          Description=tostring(properties.description),
          FailedResources=toint(properties.failedResources)
| order by FailedResources desc
```

### B) Benötigt zusätzlich Azure `Reader`

```kql
// 4. Unsichere Storage Accounts über alle Subscriptions (Public Blob, HTTP, TLS < 1.2, Shared Key)
resources
| where type =~ "microsoft.storage/storageaccounts"
| where properties.allowBlobPublicAccess != false
     or properties.supportsHttpsTrafficOnly != true
     or properties.minimumTlsVersion != "TLS1_2"
     or properties.allowSharedKeyAccess != false
| project SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Name=name,
          PublicBlob=properties.allowBlobPublicAccess,
          HTTPSOnly=properties.supportsHttpsTrafficOnly,
          MinTLS=properties.minimumTlsVersion,
          SharedKey=properties.allowSharedKeyAccess,
          NetDefault=properties.networkAcls.defaultAction
```

```kql
// 5. Key Vaults ohne Purge Protection oder ohne Azure RBAC
resources
| where type =~ "microsoft.keyvault/vaults"
| where properties.enablePurgeProtection != true or properties.enableRbacAuthorization != true
| project SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Name=name,
          PurgeProtection=properties.enablePurgeProtection,
          RBAC=properties.enableRbacAuthorization,
          PublicNet=properties.publicNetworkAccess
```
