# Kapitel 9: Azure Storage, Key Vault & Datenbank-Sicherheit

**CIS-Referenz:** CIS Microsoft Azure Foundations Benchmark (v5.x / v6.x) – *Section 8 (Key Vault)* & *Section 9 (Storage Services)* sowie *CIS Azure Database Services Benchmark*  
**Primäres Portal:** **Microsoft Azure Portal** (`https://portal.azure.com`)  
**Rollen-Hinweis:**
- **Direkte Ressourcen-CLI (`az storage`, `az keyvault`, `az sql`, `az postgres`, `az cosmosdb`):** Erfordert Azure RBAC **`Reader`** (für Key-Vault-Objekt-Metadaten wie Ablaufdaten zusätzlich **`Key Vault Reader`** bzw. Access Policy `List`).
- **Mit reinem Azure `Security Reader`:** Alle wesentlichen Storage-, Key-Vault- und SQL/DB-Fehlkonfigurationen lassen sich über **Defender for Cloud Assessments** (`securityresources`, siehe Abschnitt 9.4) auslesen!

---

## 9.1 Azure Storage Accounts (CIS Section 9)

### Erklärung & Risiko
Öffentlich lesbare Blob-Container, unverschlüsselter HTTP-Traffic, statische **Storage Account Keys** (die Entra ID / RBAC komplett umgehen!) oder fehlende Firewall-/Private-Endpoint-Restriktionen sind klassische Ursachen für Cloud-Datenlecks und Ransomware-Verschlüsselung von Backups.

### Soll-Zustand (CIS 9.1 – 9.17 / L1 & L2)
- **Secure transfer required (HTTPS only):** `enableHttpsTrafficOnly = true` *(L1)*.
- **Minimum TLS Version:** `TLS1_2` *(L1)*.
- **Allow Blob anonymous / public access:** `allowBlobPublicAccess = false` *(L1 – kritisch!)*.
- **Allow Storage Account Key access (Shared Key):** `allowSharedKeyAccess = false` → stattdessen Authentifizierung über **Microsoft Entra ID + Azure RBAC** *(L1/L2)*.
- **Public Network Access & Firewall:** `publicNetworkAccess = Disabled` (mit **Private Endpoints**) oder zumindest `networkRuleSet.defaultAction = Deny` + *Allow Azure services on the trusted services list* *(L1)*.
- **Cross-Tenant Replication:** Deaktiviert (`allowCrossTenantReplication = false`) *(L1)*.
- **Soft Delete (Blobs & Containers):** Aktiviert (mind. 7–14 Tage Retention) *(L1)*.
- **Blob Versioning & Immutable Storage (WORM):** Aktiviert für kritische/Backup-Daten *(L2)*.
- **SAS Expiration Policy:** Maximale Gültigkeit für Shared Access Signatures definiert (`sasPolicy`) *(L1)*.
- **Key Rotation Reminder:** Konfiguriert (`keyPolicy.keyExpirationPeriodInDays`, z. B. ≤ 90 Tage) *(L1)*.
- **Encryption:** Infrastructure Encryption (`requireInfrastructureEncryption = true`) *(L2)* und optional **Customer-Managed Keys (CMK)** für sensible Daten *(L2)*.
- **Azure Files (SMB):** Mindestens **SMBv3.1.1**, Channel Encryption `AES-256-GCM`, Authentifizierung via Entra Kerberos / AD DS statt Storage Account Key *(L1/L2)*.
- **Storage Logging:** Diagnostic Settings für Blob, Queue & Table (`StorageRead`, `StorageWrite`, `StorageDelete`) aktiviert *(L1/L2)*.

### Prüfung via UI (Azure Portal)
*Storage accounts* → Storage Account wählen:
1. *Settings → Configuration:* Prüfen auf **Secure transfer required**, **Minimum TLS version (1.2)**, **Allow Blob anonymous access (Disabled)**, **Allow storage account key access (Disabled)**, **Default to Microsoft Entra authorization**, **Allow cross-tenant replication (Disabled)**.
2. *Security + networking → Networking:* Prüfen auf **Public network access** (*Disabled* oder *Enabled from selected virtual networks and IP addresses*) & *Private endpoint connections*.
3. *Data management → Data protection:* **Soft delete for blobs**, **Soft delete for containers**, **Versioning** prüfen.
4. *Security + networking → Access keys:* **Set rotation reminder** prüfen.
5. *Security + networking → Encryption:* Microsoft-managed vs. Customer-managed keys & Infrastructure encryption prüfen.
6. *Monitoring → Diagnostic settings:* Logging für `blob`, `file`, `queue`, `table` prüfen.

### Prüfung via CLI (erfordert Azure `Reader`)

```bash
# Alle Storage Accounts mit den wichtigsten CIS-Sicherheitsparametern prüfen
az storage account list --query "[].{
    Name:name,
    RG:resourceGroup,
    HTTPSOnly:enableHttpsTrafficOnly,
    MinTLS:minimumTlsVersion,
    PublicBlob:allowBlobPublicAccess,
    SharedKey:allowSharedKeyAccess,
    PublicNet:publicNetworkAccess,
    NetDefault:networkRuleSet.defaultAction,
    CrossTenantRepl:allowCrossTenantReplication,
    InfraEnc:encryption.requireInfrastructureEncryption,
    KeyExpDays:keyPolicy.keyExpirationPeriodInDays
}" -o table

# Soft Delete & Versioning pro Storage Account prüfen (Beispielschleife)
for row in $(az storage account list --query "[].{name:name, rg:resourceGroup}" -o tsv | tr '\t' ':'); do
  NAME="${row%%:*}"
  RG="${row##*:}"
  echo "=== $NAME ($RG) ==="
  az storage account blob-service-properties show --account-name "$NAME" --resource-group "$RG" \
    --query "{DeleteRetention:deleteRetentionPolicy, ContainerDeleteRetention:containerDeleteRetentionPolicy, Versioning:isVersioningEnabled}" -o json
done
```

---

## 9.2 Azure Key Vault (CIS Section 8.3)

### Erklärung & Risiko
Azure Key Vault speichert Geheimnisse, API-Keys, TLS-Zertifikate und Verschlüsselungsschlüssel (CMK). Fehlt **Purge Protection**, kann ein Angreifer nach einer Kompromittierung Schlüssel unwiederbringlich löschen (Denial-of-Service / Ransomware). Das veraltete **Access Policy**-Modell ist zudem weniger granular als **Azure RBAC** (und `Contributor` kann sich selbst Access Policies gewähren!).

### Soll-Zustand (CIS 8.3.x / L1 & L2)
- **Permission Model:** **Azure role-based access control (RBAC)** statt Legacy Vault Access Policies (`enableRbacAuthorization = true`) *(L1)*.
- **Soft Delete:** Aktiviert (`enableSoftDelete = true`, heute Standard) *(L1)*.
- **Purge Protection:** **Aktiviert** (`enablePurgeProtection = true`) *(L1 – extrem häufiges Finding!)*
- **Netzwerkzugriff:** `publicNetworkAccess = Disabled` (mit **Private Endpoints**) oder Firewall `networkAcls.defaultAction = Deny` *(L1)*.
- **Ablaufdaten & Rotation:** Alle **Keys**, **Secrets** und **Zertifikate** besitzen ein gesetztes Ablaufdatum (`exp`) und nach Möglichkeit Auto-Rotation *(L1)*.
- **Diagnostic Logging:** Kategorie `AuditEvent` wird an Log Analytics Workspace exportiert *(L1)*.
- **Microsoft Defender for Key Vault:** Aktiviert (siehe Kapitel 7.2) *(L2)*.

### Prüfung via UI (Azure Portal)
*Key vaults* → Key Vault wählen:
1. *Settings → Access configuration:* Prüfen, ob **Azure role-based access control** aktiv ist (falls *Vault access policy*: unter *Access policies* auf übermäßige Berechtigungen wie `All` oder verdächtige Principals achten!).
2. *Settings → Properties:* **Soft-delete** und **Purge protection (Enabled)** prüfen.
3. *Settings → Networking:* **Public access** (*Disable* oder *Allow from selected networks*) & *Private endpoint connections*.
4. *Monitoring → Diagnostic settings:* Export von `AuditEvent` prüfen.
5. *Objects → Keys / Secrets / Certificates:* *(Erfordert `Key Vault Reader` oder Access Policy `List`)* Ablaufdaten prüfen.

### Prüfung via CLI

```bash
# 1. Alle Key Vaults & Control-Plane-Sicherheit prüfen (erfordert Azure Reader)
az keyvault list --query "[].{
    Name:name,
    RG:resourceGroup,
    RBAC:properties.enableRbacAuthorization,
    SoftDelete:properties.enableSoftDelete,
    PurgeProtection:properties.enablePurgeProtection,
    PublicNet:properties.publicNetworkAccess,
    NetDefault:properties.networkAcls.defaultAction
}" -o table

# 2. Diagnostic Settings eines Key Vaults prüfen (erfordert Azure Reader)
# az monitor diagnostic-settings list --resource "<KEYVAULT_RESOURCE_ID>" -o json

# 3. Secrets / Keys OHNE Ablaufdatum prüfen (erfordert Key Vault Reader bei RBAC-Vaults!)
# az keyvault secret list --vault-name "<VAULT_NAME>" --query "[?attributes.expires==null].{Name:name, Enabled:attributes.enabled}" -o table
# az keyvault key list --vault-name "<VAULT_NAME>" --query "[?attributes.expires==null].{Name:name, Enabled:attributes.enabled}" -o table
```

---

## 9.3 Datenbanken: Azure SQL, PostgreSQL, MySQL & Cosmos DB

### Erklärung & Risiko
Datenbanken enthalten die wertvollsten Geschäftsdaten. Ein sehr häufiges Finding in Azure SQL ist die aktivierte Firewall-Ausnahme **`0.0.0.0` („Allow Azure services and resources to access this server“)** – sie erlaubt Verbindungen von **jedem beliebigen Azure-Tenant weltweit**, nicht nur vom eigenen! Ebenso kritisch sind lokale SQL-Passwörter statt Microsoft Entra ID Authentication und fehlendes Auditing.

### Soll-Zustand (CIS Azure Database Services Benchmark / L1 & L2)
- **Azure SQL Server & Databases:**
  - **Microsoft Entra-only Authentication** aktiviert (`azureADOnlyAuthentication = true`) und Entra Admin gesetzt *(L1)*.
  - **Public Network Access:** Deaktiviert (Private Endpoints) *(L1/L2)*. Falls öffentlich: **keine** Firewall-Regel `0.0.0.0` (*AllowAllWindowsAzureIps*) und **keine** `0.0.0.0 – 255.255.255.255` Regel! *(L1 – kritisch!)*.
  - **Minimum TLS Version:** `1.2` *(L1)*.
  - **Auditing:** Aktiviert (Server- oder DB-Ebene, Export nach Log Analytics / Storage mit ≥ 90 Tagen Retention) *(L1)*.
  - **Transparent Data Encryption (TDE):** Aktiviert (`Enabled`), idealerweise mit **Customer-Managed Keys (CMK)** *(L1/L2)*.
  - **Defender for SQL & Vulnerability Assessment:** Aktiviert, wiederkehrende Scans + E-Mail-Benachrichtigung konfiguriert *(L2)*.
- **Azure Database for PostgreSQL / MySQL (Flexible Server):**
  - `require_secure_transport = ON` (TLS erzwungen, mindestens TLS 1.2) *(L1)*.
  - PostgreSQL Logging: `log_checkpoints = ON`, `log_connections = ON`, `log_disconnections = ON`, `connection_throttling = ON`, `log_retention_days ≥ 4` (plus Export via Diagnostic Settings) *(L1)*.
  - Private Access (VNet Integration / Private Endpoint) statt Public Access; keine `0.0.0.0` Firewall-Regel *(L1)*.
  - Microsoft Entra Authentication aktiviert *(L1)*.
- **Azure Cosmos DB:**
  - `disableLocalAuth = true` (keine statischen Master-Keys, nur Entra ID RBAC!) *(L1)*.
  - `publicNetworkAccess = Disabled` (Private Endpoints) oder strikte IP-Firewall *(L1)*.

### Prüfung via UI (Azure Portal)
1. **SQL Server:** *SQL servers* → Server öffnen:
   - *Security → Microsoft Entra ID:* Admin gesetzt & „Support only Microsoft Entra authentication“ prüfen.
   - *Security → Networking:* **Public network access**, **Allow Azure services… (muss AUS sein!)** und **Firewall rules** prüfen.
   - *Security → Auditing:* Status `On` & Ziel (Log Analytics/Storage) prüfen.
   - *Security → Microsoft Defender for Cloud:* Status & Vulnerability Assessment prüfen.
   - *Security → Transparent data encryption:* Service-managed vs. Customer-managed prüfen.
   - *Settings → Connection security / Minimum TLS version:* `TLS 1.2`.
2. **PostgreSQL / MySQL Flexible Server:** *Settings → Networking* (Public Access / Firewall), *Settings → Server parameters* (`require_secure_transport`, `log_connections`, `log_checkpoints`, `tls_version`), *Security → Authentication*.
3. **Cosmos DB:** *Settings → Networking* & *Settings → Keys* (Local Auth deaktiviert?).

### Prüfung via CLI (erfordert Azure `Reader`)

```bash
# 1. Azure SQL Server Übersicht (TLS, Public Access, Entra-only Auth)
az sql server list --query "[].{
    Name:name,
    RG:resourceGroup,
    MinTLS:minimalTlsVersion,
    PublicNet:publicNetworkAccess,
    EntraAdmin:administrators.login,
    EntraOnly:administrators.azureAdOnlyAuthentication
}" -o table

# 2. Gefährliche SQL Firewall-Regeln finden (0.0.0.0 oder 0.0.0.0-255.255.255.255!)
for row in $(az sql server list --query "[].{name:name, rg:resourceGroup}" -o tsv | tr '\t' ':'); do
  NAME="${row%%:*}"
  RG="${row##*:}"
  echo "=== SQL Firewall: $NAME ==="
  az sql server firewall-rule list --server "$NAME" --resource-group "$RG" \
    --query "[].{Rule:name, StartIP:startIpAddress, EndIP:endIpAddress}" -o table
  echo "=== SQL Auditing: $NAME ==="
  az sql server audit-policy show --name "$NAME" --resource-group "$RG" \
    --query "{State:state, LogAnalytics:isAzureMonitorTargetEnabled, RetentionDays:retentionDays}" -o json
done

# 3. PostgreSQL Flexible Server prüfen
az postgres flexible-server list --query "[].{
    Name:name,
    RG:resourceGroup,
    PublicAccess:network.publicNetworkAccess,
    EntraAuth:authConfig.activeDirectoryAuth,
    PasswordAuth:authConfig.passwordAuth
}" -o table

# 4. Cosmos DB Local Auth & Public Network Access prüfen
az cosmosdb list --query "[].{
    Name:name,
    RG:resourceGroup,
    DisableLocalAuth:disableLocalAuth,
    PublicNet:publicNetworkAccess
}" -o table
```

---

## 9.4 Workaround bei reinem Azure `Security Reader` (ohne Azure `Reader`)

Mit reinem Azure `Security Reader` kannst du fehlkonfigurierte Storage Accounts, Key Vaults und Datenbanken über **Defender for Cloud Assessments** in Azure Resource Graph identifizieren:

```bash
# Funktioniert mit reinem Azure Security Reader!
az graph query -q "
securityresources
| where type == 'microsoft.security/assessments'
| where properties.status.code == 'Unhealthy'
| where properties.displayName has_any ('Storage', 'Blob', 'Key Vault', 'SQL', 'PostgreSQL', 'MySQL', 'Cosmos', 'database', 'encryption', 'purge', 'firewall', 'TLS')
| project SubscriptionId=subscriptionId,
          Assessment=tostring(properties.displayName),
          Severity=tostring(properties.metadata.severity),
          ResourceId=tostring(properties.resourceDetails.Id)
| order by Severity desc
" --first 250 -o table
```
