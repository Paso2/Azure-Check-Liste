# Kapitel 7: Azure Governance, RBAC, Policy, Logging & Microsoft Defender for Cloud

**CIS-Referenz:** CIS Microsoft Azure Foundations Benchmark (v5.x / v6.x) – *Section 5 (Identity / Azure RBAC)*, *Section 6 (Management & Governance / Logging)* & *Section 8 (Security Services / Defender for Cloud)*  
**Primäres Portal:** **Microsoft Azure Portal** (`https://portal.azure.com`)  
**Erforderliche Rollen:** Azure RBAC `Security Reader` (auf Management Group / Subscription) ✅  
*(Fast alle Kontrollen in diesem Kapitel funktionieren **direkt** mit Azure `Security Reader`, da die Rolle `Microsoft.Authorization/*/read`, `Microsoft.Security/*/read`, `Microsoft.Management/managementGroups/read`, `Microsoft.operationalInsights/workspaces/*/read` und `Microsoft.Insights/alertRules/read` enthält!)*

---

## 7.1 Management Groups, Subscriptions & Azure RBAC Audit (CIS Section 5)

### Erklärung & Risiko
Unkontrollierte **Owner**- oder **Contributor**-Zuweisungen auf Subscription- oder Management-Group-Ebene ermöglichen die Übernahme sämtlicher Cloud-Workloads, Daten und Netzwerke. Häufige Altlasten sind **Classic Administrators (Co-Administrators)**, Wildcard Custom Roles (`*`), direkte Zuweisungen an Einzelpersonen statt Gruppen sowie vergessene **Gastkonten** oder **Service Principals** mit Owner-Rechten.

### Soll-Zustand (CIS Azure Section 5 / L1 & L2)
- **Subscription Owners:** Maximal **3** Owners pro Subscription; idealerweise über **PIM for Azure Resources** als *Eligible* (nicht dauerhaft *Active*) *(L1/L2)*.
- **Classic Subscription Administrators (Co-Administrators):** Keine vorhanden (0) – vollständig auf Azure RBAC migriert *(L1)*.
- **Custom Subscription Administrator Roles:** Keine benutzerdefinierten Rollen mit `actions: ["*"]` auf Subscription-/Management-Group-Ebene *(L1)*.
- **Least Privilege & Gruppen-Prinzip:** Rollenzuweisungen erfolgen über Entra-Sicherheitsgruppen, nicht an Einzelpersonen; keine Gastkonten (`#EXT#`) mit privilegierten Rollen (`Owner`, `Contributor`, `User Access Administrator`) *(L1/L2)*.
- **Service Principals & Managed Identities:** Prüfen auf überprivilegierte `Owner` / `User Access Administrator` / `Contributor` Zuweisungen auf Subscription-Ebene (klassisches Risiko bei CI/CD-Pipelines!).
- **Resource Locks:** Kritische Produktions-Ressourcen (z. B. Key Vaults, Backup Vaults, Firewalls, Core-VNets, Log Analytics) sind durch `CanNotDelete`-Locks geschützt *(L2)*. *(Hinweis: Locks-Abfrage `az lock list` benötigt ggf. Azure `Reader`.)*

### Prüfung via UI (Azure Portal – `portal.azure.com`)
1. **Management Groups:** Suche nach *Management groups* → Hierarchie & *Access control (IAM)* auf Root/Sub-Ebenen prüfen.
2. **Subscription IAM:** *Subscriptions* → Subscription wählen → *Access control (IAM)*:
   - Reiter **Role assignments** → nach Rolle `Owner`, `Contributor`, `User Access Administrator`, `Role Based Access Control Administrator` filtern.
   - Reiter **Classic administrators** → muss leer sein!
   - Reiter **Roles** → Filter *Type = CustomRole* → JSON der Custom Roles auf `actions: ["*"]` prüfen.
3. **PIM for Azure Resources:** *Microsoft Entra Privileged Identity Management → Azure resources* → prüfen, ob Subscriptions in PIM eingebunden sind.

### Prüfung via CLI (Azure CLI – funktioniert mit Azure `Security Reader`!)

```bash
# 1. Alle Subscriptions auflisten
az account list --query "[].{Name:name, Id:id, State:state, Tenant:tenantId}" -o table

# 2. Management Group Struktur anzeigen
az account management-group list -o table

# 3. Alle hochprivilegierten Azure RBAC Role Assignments (Owner, Contributor, UAA) in der aktiven Subscription
az role assignment list --all \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='User Access Administrator' || roleDefinitionName=='Contributor'].{Role:roleDefinitionName, Principal:principalName, Type:principalType, Scope:scope}" \
  -o table

# 4. Benutzerdefinierte Rollen (Custom Roles) mit Wildcard '*' finden
az role definition list --custom-role-only true \
  --query "[].{Name:roleName, Actions:permissions[0].actions, Scopes:assignableScopes}" -o json

# 5. Classic Administrators prüfen (Legacy-REST-API)
SUB_ID=$(az account show --query id -o tsv)
az rest --method GET \
  --url "https://management.azure.com/subscriptions/${SUB_ID}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-07-01" \
  --query "value[].{Email:properties.emailAddress, Role:properties.role}" -o table
```

---

## 7.2 Microsoft Defender for Cloud – Secure Score, CIS Compliance & Defender Plans (CIS Section 8)

### Erklärung & Risiko
**Microsoft Defender for Cloud** ist die zentrale Cloud Security Posture Management (CSPM) & Workload Protection (CWPP) Plattform in Azure – und gleichzeitig **dein wichtigstes Werkzeug mit der Rolle `Security Reader`**! Hier erhältst du den aktuellen **Secure Score**, **Attack Paths**, den Status aller **Defender-Pläne** sowie das automatisierte **Regulatory Compliance Mapping auf den CIS Microsoft Azure Foundations Benchmark**.

### Soll-Zustand (CIS Azure Section 8.1 / L1 & L2)
- **Defender CSPM** (oder Foundational CSPM) aktiviert *(L2 / Best Practice)*.
- **Microsoft Defender Plans (je nach vorhandenen Workloads aktiviert):**
  - *Defender for Servers* (Plan 2 für Vulnerability Management & FIM) *(L2)*
  - *Defender for App Service* *(L2)*
  - *Defender for Databases* (Azure SQL, SQL on Machines, Open-Source Relational DBs, Cosmos DB) *(L2)*
  - *Defender for Storage* (inkl. Malware Scanning / Sensitive Data Discovery bei Bedarf) *(L2)*
  - *Defender for Containers* *(L2)*
  - *Defender for Key Vault* *(L2)*
  - *Defender for Azure Resource Manager (ARM)* *(L2)*
  - *Defender for DNS* (jetzt Teil von Defender for Servers P2 / CSPM) *(L2)*
- **Security Contacts (E-Mail-Benachrichtigungen):**
  - Mindestens eine gültige Security-Kontakt-E-Mail-Adresse (SOC/Team-Verteiler) hinterlegt *(L1)*.
  - *Notify about alerts with severity:* mindestens **High** (besser Medium/High) *(L1)*.
  - *Notify about attack paths* aktiviert *(L1)*.
  - *Send email notification to subscription owners* aktiviert *(L1)*.
- **Regulatory Compliance:** CIS Microsoft Azure Foundations Benchmark & Microsoft Cloud Security Benchmark (MCSB) sind zugewiesen und werden aktiv überwacht.
- **Continuous Export / SIEM-Anbindung:** Alerts & Recommendations werden nach Log Analytics / Microsoft Sentinel exportiert.

### Prüfung via UI (Azure Portal – `portal.azure.com`)
1. Suche nach **Microsoft Defender for Cloud**:
   - **Overview / Secure Score:** Gesamt-Score (in %) je Subscription und Top-Empfehlungen prüfen.
   - **Management → Environment settings → Subscription wählen**:
     - *Defender plans* → Status (`On`/`Off`, Plan 1 vs. Plan 2, Sub-Einstellungen wie Vulnerability Assessment & Agentless Scanning).
     - *Email notifications* → Security Contacts, Severity Threshold & „Notify Owners“ prüfen.
     - *Continuous export* → Export-Konfiguration zu Log Analytics / Event Hub prüfen.
     - *Security policies* → Prüfen, welche Standards (MCSB, CIS Azure Benchmark, ISO 27001, NIS2) aktiviert sind.
   - **Cloud Security → Regulatory compliance:** Reiter *CIS Microsoft Azure Foundations Benchmark* öffnen und Passed/Failed Controls exportieren!
   - **Cloud Security → Recommendations & Attack path analysis:** Kritische Pfade (z. B. *Internet-exposed VM with high severity vulnerabilities and high-privilege Managed Identity*) dokumentieren.

### Prüfung via CLI (Azure CLI – funktioniert vollständig mit Azure `Security Reader`!)

```bash
# 1. Secure Score aller sichtbaren Subscriptions abrufen
az security secure-scores list --query "[].{Name:displayName, Current:score.current, Max:score.max, Pct:score.percentage}" -o table

# 2. Defender Plans (Pricing Tiers) prüfen (Free = deaktiviert, Standard = aktiviert!)
az security pricing list --query "value[].{Plan:name, Tier:pricingTier, SubPlan:subPlan}" -o table

# 3. Security Contacts / E-Mail-Benachrichtigungen prüfen
az security contact list -o json

# 4. Auto-Provisioning & Defender Settings prüfen
az security auto-provisioning-setting list -o table
az security setting list -o table

# 5. Regulatory Compliance Standards & Ergebnisse abrufen (inkl. CIS Benchmark!)
az security regulatory-compliance-standards list \
  --query "[].{Standard:name, State:state, Passed:passedControls, Failed:failedControls, Unsupported:unsupportedControls}" -o table

# 6. Alle fehlgeschlagenen (Unhealthy) Defender Assessments auflisten (extrem wertvoll ohne Reader-Rolle!)
az security assessment list \
  --query "[?status.code=='Unhealthy'].{Assessment:displayName, Status:status.code, Resource:resourceDetails.Id}" -o table
```

> [!TIP]
> **Power-Query via Azure Resource Graph (`securityresources`):**
> Mit Azure `Security Reader` kannst du über `az graph query` die Tabelle `securityresources` über **alle Subscriptions gleichzeitig** in Sekunden abfragen! Siehe [Kapitel 11](./11-automatisierte-pruefskripte-und-tools.md) und [`scripts/kql-resource-graph-queries.kql`](../scripts/kql-resource-graph-queries.kql).

---

## 7.3 Azure Policy & Governance Compliance (CIS Section 6)

### Erklärung & Risiko
Azure Policy erzwingt Sicherheits-Leitplanken präventiv (`Deny` / `DeployIfNotExists`) oder detektiv (`Audit`). Ohne aktive Policy Assignments driften Cloud-Umgebungen durch neue Deployments sehr schnell von der Sicherheits-Baseline weg.

### Soll-Zustand
- Zuweisung der **Microsoft Cloud Security Benchmark (MCSB)** Initiative (Standard durch Defender for Cloud) sowie idealerweise der **CIS Azure Benchmark** Initiative.
- Präventive Guardrails (`Deny`) für kritische Risiken (z. B. *Allowed Locations*, *Deny Public Blob Access*, *Require HTTPS on Storage*, *Require TLS 1.2*, *Deny Public IP on NICs*).
- Aktive Überwachung von `NonCompliant`-Ressourcen und dokumentierte Policy Exemptions (keine abgelaufenen oder pauschalen Ausnahmen).

### Prüfung via UI (Azure Portal)
- Suche nach **Policy**:
  - *Authoring → Assignments* → zugewiesene Initiativen/Policies & Enforcement Mode (`Enabled` vs. `Disabled`) prüfen.
  - *Authoring → Exemptions* → prüfen, ob kritische Kontrollen pauschal ausgenommen wurden.
  - *Compliance* → Compliance-Prozentwert & Top-Non-Compliant-Policies prüfen.

### Prüfung via CLI (funktioniert mit Azure `Security Reader`!)

```bash
# 1. Alle Policy Assignments in der Subscription anzeigen
az policy assignment list --query "[].{Name:displayName, Enforcement:enforcementMode, Scope:scope}" -o table

# 2. Policy Compliance Summary (Non-Compliant Ressourcen je Policy zählen)
az policy state summarize --query "policyAssignments[].{Policy:policyAssignmentId, NonCompliantResources:results.nonCompliantResources}" -o table

# 3. Policy Exemptions prüfen (via REST API)
SUB_ID=$(az account show --query id -o tsv)
az rest --method GET \
  --url "https://management.azure.com/subscriptions/${SUB_ID}/providers/Microsoft.Authorization/policyExemptions?api-version=2022-07-01-preview" \
  --query "value[].{Name:name, Category:properties.exemptionCategory, Expires:properties.expiresOn, Description:properties.description}" -o table
```

---

## 7.4 Logging, Monitoring, Activity Log Alerts & SIEM (CIS Section 6.1)

### Erklärung & Risiko
Das Azure Activity Log speichert Control-Plane-Ereignisse standardmäßig nur **90 Tage** und ist nicht durchsuchbar/korrelierbar wie ein SIEM. Zudem müssen sicherheitskritische Änderungen (z. B. Löschen einer NSG, Öffnen der SQL-Firewall, Deaktivieren einer Security Policy) sofort **Activity Log Alerts** auslösen.

### Soll-Zustand (CIS Azure Section 6.1.x / L1 & L2)
- **Subscription Diagnostic Settings:** Activity Log wird an einen **Log Analytics Workspace** (oder Storage Account / Event Hub) exportiert und umfasst mindestens die Kategorien: `Administrative`, `Alert`, `Policy`, `Security` *(L1)*.
- **Diagnostic Setting für Key Vault & Netzwerkressourcen:** Aktiviert *(L1)*.
- **Activity Log Alerts eingerichtet für (CIS 6.1.2.x / L1):**
  1. Create or Update Policy Assignment / Delete Policy Assignment
  2. Create or Update Network Security Group / Delete NSG
  3. Create or Update Security Solution / Delete Security Solution
  4. Create or Update SQL Server Firewall Rule / Delete SQL Server Firewall Rule
  5. Create or Update Public IP Address Rule / Delete Public IP Address
  6. Service Health Incidents *(L1)*
- **Log Analytics Workspace & Microsoft Sentinel:** Aufbewahrungsdauer (Retention) ≥ 90–365 Tage; Datenkonnektoren (Entra ID, Azure Activity, Defender for Cloud, M365 Defender) aktiv.

### Prüfung via UI (Azure Portal)
1. **Activity Log Export:** *Monitor → Activity log → Export Activity Logs (Diagnostic settings)* → prüfen, ob für jede Subscription ein Diagnostic Setting mit `Administrative`, `Security`, `Alert`, `Policy` existiert.
2. **Activity Log Alerts:** *Monitor → Alerts → Alert rules* → Filter nach *Signal type = Activity Log* → gegen die CIS-Liste (Policy, NSG, Security Solution, SQL Firewall, Public IP, Service Health) abgleichen.
3. **Log Analytics & Sentinel:** *Log Analytics workspaces* (Retention prüfen) & *Microsoft Sentinel* (falls im Einsatz: Data Connectors & Analytics Rules prüfen).

### Prüfung via CLI

```bash
# 1. Activity Log Alert Rules auflisten (funktioniert mit Security Reader: Microsoft.Insights/alertRules/read)
az monitor activity-log alert list \
  --query "[].{Name:name, Enabled:enabled, Condition:condition.allOf[].equals}" -o json

# 2. Log Analytics Workspaces & Retention prüfen (funktioniert mit Security Reader!)
az monitor log-analytics workspace list \
  --query "[].{Name:name, RG:resourceGroup, RetentionDays:retentionInDays, SKU:sku.name}" -o table

# 3. Subscription Diagnostic Settings prüfen
# Hinweis: Erfordert Microsoft.Insights/diagnosticSettings/read (mit Azure Reader direkt; bei reinem Security Reader ggf. über Defender Assessment prüfen!)
SUB_ID=$(az account show --query id -o tsv)
az monitor diagnostic-settings subscription list --subscription "$SUB_ID" -o json
```
