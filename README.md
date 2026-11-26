# Microsoft Azure & Microsoft 365 Security Assessment – Konfigurationsanalyse (CIS Benchmarks)

Umfassender Praxis-Leitfaden zur Durchführung einer **Microsoft Azure & Microsoft 365 Konfigurationsanalyse** mit den Read-Only-Rollen **Global Reader** und **Security Reader**, orientiert an den aktuellen **CIS Benchmarks**:

- **CIS Microsoft 365 Foundations Benchmark** *(v5.x / v6.x / v7.x)*
- **CIS Microsoft Azure Foundations Benchmark** *(v5.x / v6.x)*
- Ergänzend: **CIS Azure Compute, Database & Storage Services Benchmarks**

Jeder Prüfpunkt ist konsequent aufgebaut nach:
1. **Erklärung & Risiko** *(Warum prüfen wir das?)*
2. **Soll-Zustand nach CIS Benchmark** *(Level 1 vs. Level 2)*
3. **Prüfungsort** *(Microsoft Entra Admin Center vs. Azure Portal vs. M365 / Defender / Purview / Exchange / SharePoint / Teams / Intune / Fabric)*
4. **Prüfung über die UI** *(exakter Klickpfad)*
5. **Prüfung über CLI / PowerShell** *(reproduzierbare, rein lesende Befehle)*
6. **Rollen- & Berechtigungshinweise** *(Was geht mit `Global Reader` + `Security Reader`, und wo greifen harte Microsoft-Grenzen bzw. Workarounds?)*

---

## Schnellübersicht: Kapitelstruktur

| Kapitel | Thema | Primäres Portal | CIS-Zuordnung |
| :---: | :--- | :--- | :--- |
| **01** | [Vorbereitung, Rollenmodell, Berechtigungsgrenzen & Tooling](docs/01-vorbereitung-rollen-und-tools.md) | Alle Portale | Methodik, CIS L1/L2, RBAC-Grenzen, CLI-Setup |
| **02** | [Microsoft Entra ID – Identitäten, Authentifizierung & Zugriffskontrolle](docs/02-entra-id-identitaeten-und-zugriff.md) | **Entra Admin Center** (`entra.microsoft.com`) | CIS M365 Section 5 & Azure Identity |
| **03** | [Microsoft 365 Admin Center – Tenant-Grundlagen & Governance](docs/03-m365-admin-center-und-governance.md) | **M365 Admin Center** (`admin.microsoft.com`) | CIS M365 Section 1 |
| **04** | [E-Mail-Sicherheit – Exchange Online & Defender for Office 365](docs/04-exchange-online-und-defender-for-office365.md) | **Exchange Admin** & **Defender Portal** (`security.microsoft.com`) | CIS M365 Sections 2 & 6 |
| **05** | [Kollaboration – SharePoint, OneDrive, Teams & Fabric/Power BI](docs/05-sharepoint-onedrive-teams-und-fabric.md) | **SharePoint**, **Teams** & **Fabric Admin** | CIS M365 Sections 7, 8 & 9 |
| **06** | [Compliance & Endgeräte – Microsoft Purview & Microsoft Intune](docs/06-purview-und-intune.md) | **Purview** (`purview.microsoft.com`) & **Intune** (`intune.microsoft.com`) | CIS M365 Sections 3 & 4 |
| **07** | [Azure Governance, RBAC, Policy, Logging & Defender for Cloud](docs/07-azure-governance-rbac-und-defender-for-cloud.md) | **Azure Portal** (`portal.azure.com`) | CIS Azure Sections 5, 6 & 8 |
| **08** | [Azure Netzwerksicherheit (NSGs, Public IPs, Bastion, Flow Logs, WAF)](docs/08-azure-netzwerk-sicherheit.md) | **Azure Portal** (`portal.azure.com`) | CIS Azure Section 7 |
| **09** | [Azure Storage, Key Vault & Datenbank-Sicherheit (SQL, PG, Cosmos)](docs/09-azure-storage-keyvault-und-datenbanken.md) | **Azure Portal** (`portal.azure.com`) | CIS Azure Sections 8, 9 & DB |
| **10** | [Azure Compute (VMs), App Service, Container (AKS/ACR) & Analytics](docs/10-azure-compute-appservice-und-container.md) | **Azure Portal** (`portal.azure.com`) | CIS Azure Sections 2, 3 & Compute |
| **11** | [Automatisierung, Open-Source-Tools & Resource Graph (KQL)](docs/11-automatisierte-pruefskripte-und-tools.md) | CLI / PowerShell / Resource Graph | Maester, Prowler, ScubaGear, EntraFalcon |
| **12** | [Bewertung, Reporting, Finding-Template & Master-Checkliste](docs/12-bewertung-reporting-und-checkliste.md) | Berichtswesen | Risikomatrix, Finding-Template, Abhakliste |

---

## Auf einen Blick: Entra ID vs. Azure vs. M365 Portale

```mermaid
flowchart LR
    subgraph Entra["Microsoft Entra Admin Center (entra.microsoft.com)"]
        E1["Conditional Access & MFA"]
        E2["Global Admins & PIM"]
        E3["Apps, Consent & Gaeste"]
        E4["Identity Protection & Hybrid"]
    end

    subgraph M365["Microsoft 365 Portale"]
        M1["M365 Admin (admin.microsoft.com)"]
        M2["Defender Portal (security.microsoft.com)"]
        M3["Exchange / SharePoint / Teams"]
        M4["Purview & Intune"]
    end

    subgraph Azure["Microsoft Azure Portal (portal.azure.com)"]
        A1["Azure RBAC & Policy"]
        A2["Defender for Cloud & Logging"]
        A3["Networking (NSG, WAF, VNet)"]
        A4["Storage, Key Vault, DB, Compute"]
    end

    Entra --- M365
    Entra --- Azure
```

---

## Wichtige Besonderheiten bei `Global Reader` + `Security Reader`

Vor Beginn jedes Assessments unbedingt beachten (Details in [Kapitel 1](docs/01-vorbereitung-rollen-und-tools.md)):

1. **`Security Reader` existiert zweimal:**
   - **Entra ID `Security Reader`** → liest Microsoft Defender Portal (inkl. Secure Score), Identity Protection & PIM.
   - **Azure RBAC `Security Reader`** (auf Management Group / Subscription) → liest Defender for Cloud (Secure Score, CIS Compliance, Assessments), Azure RBAC, Azure Policy, Log Analytics und Alert Rules.
2. **Azure RBAC `Security Reader` enthält KEIN `*/read`:**
   - Direkte Ressourcen-Abfragen wie `az storage account list`, `az network nsg list` oder `az keyvault list` erfordern zusätzlich Azure RBAC **`Reader`** auf der Subscription / Management Group.
   - **Workaround ohne `Reader`:** Alle Kapitel 8–10 enthalten fertige **Defender for Cloud / Azure Resource Graph (`securityresources`)** Queries, mit denen die Fehlkonfigurationen trotzdem sichtbar werden!
3. **SharePoint Online PowerShell (`Get-SPOTenant`):**
   - Schlägt mit reinem `Global Reader` i. d. R. fehl → stattdessen über das **SharePoint Admin Center (UI)** oder die **Microsoft Graph API** (`Get-MgAdminSharepointSetting` / `/v1.0/admin/sharepoint/settings`) prüfen.
4. **Microsoft Fabric / Power BI & Purview:**
   - Fabric Tenant Settings erfordern häufig einen *Fabric Administrator* (ggf. per Kunden-Screenshare prüfen).
   - Purview-Bereiche (DLP/Labels) über `Connect-IPPSSession` mit `Security Reader` + `Global Reader` testen.

---

## Mitgelieferte Read-Only-Skripte (`scripts/`)

Alle Skripte im Ordner [`scripts/`](scripts/) führen **ausschließlich schreibgeschützte Lese-Operationen** durch:

| Datei | Beschreibung | Aufruf |
| :--- | :--- | :--- |
| [`scripts/audit-azure-security-reader.sh`](scripts/audit-azure-security-reader.sh) | Bash + Azure CLI Collector für alle Subscriptions (erkennt automatisch `Security Reader` vs. `Reader`) | `az login --tenant <TID> && ./scripts/audit-azure-security-reader.sh` |
| [`scripts/audit-m365-entra-reader.ps1`](scripts/audit-m365-entra-reader.ps1) | PowerShell 7 Collector für Entra ID (Graph), Exchange Online, Defender for O365, SharePoint (Graph), Teams, Intune & optional Purview | `pwsh ./scripts/audit-m365-entra-reader.ps1 -TenantId <TID> -UserPrincipalName <UPN>` |
| [`scripts/kql-resource-graph-queries.kql`](scripts/kql-resource-graph-queries.kql) | Fertige Azure Resource Graph KQL-Abfragen (getrennt nach `Security Reader` und `Reader`) | Direkt im Azure Portal (*Resource Graph Explorer*) oder via `az graph query` |

---

## Empfohlener Assessment-Ablauf

1. **Kick-off & Rollen-Check ([Kapitel 1](docs/01-vorbereitung-rollen-und-tools.md)):** Eigene Rollen, Lizenzen, Domains & Hybrid-Status erfassen; prüfen ob Azure `Reader` zusätzlich gewährt wird.
2. **Automatisierte Datensammlung ([Kapitel 11](docs/11-automatisierte-pruefskripte-und-tools.md)):** `audit-m365-entra-reader.ps1` + `audit-azure-security-reader.sh` (und optional *Maester* / *Prowler*) ausführen.
3. **Tiefenprüfung nach Priorität:**
   - Identitäten & Zugriff ([Kapitel 2](docs/02-entra-id-identitaeten-und-zugriff.md))
   - E-Mail & Defender for Office 365 ([Kapitel 4](docs/04-exchange-online-und-defender-for-office365.md))
   - M365 Admin, SharePoint, Teams, Fabric, Purview & Intune ([Kapitel 3](docs/03-m365-admin-center-und-governance.md), [5](docs/05-sharepoint-onedrive-teams-und-fabric.md), [6](docs/06-purview-und-intune.md))
   - Azure Governance, Defender for Cloud, Netzwerk, Storage, Key Vault, DBs & Compute ([Kapitel 7–10](docs/07-azure-governance-rbac-und-defender-for-cloud.md))
4. **Konsolidierung & Reporting ([Kapitel 12](docs/12-bewertung-reporting-und-checkliste.md)):** Findings anhand der Risikomatrix priorisieren, Master-Checkliste vervollständigen und Kundenbericht erstellen.