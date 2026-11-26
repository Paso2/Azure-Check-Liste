# Kapitel 10: Azure Compute (VMs), App Service, Container (AKS/ACR) & Analytics

**CIS-Referenz:** CIS Microsoft Azure Foundations Benchmark (v5.x / v6.x) – *Section 2 (Analytics)* & *Section 3 (Compute)* sowie *CIS Microsoft Azure Compute Services Benchmark*  
**Primäres Portal:** **Microsoft Azure Portal** (`https://portal.azure.com`)  
**Rollen-Hinweis:**
- **Direkte Ressourcen-CLI (`az vm`, `az webapp`, `az aks`, `az acr`, `az synapse`):** Erfordert Azure RBAC **`Reader`**.
- **Mit reinem Azure `Security Reader`:** Nutze die **Defender for Cloud Assessments** (Abschnitt 10.5) für VM-Schwachstellen, fehlende Disk Encryption, App-Service-TLS/HTTPS/FTP-Mängel und AKS/ACR-Befunde!

---

## 10.1 Virtual Machines (VMs)

### Erklärung & Risiko
Ungepatchte VMs, unverschlüsselte Disks, fehlender Endpoint-Schutz, nicht genehmigte VM-Extensions oder überprivilegierte Managed Identities bilden häufig die Brücke von einem kompromittierten Dienst in die gesamte Azure-Subscription.

### Soll-Zustand (CIS Compute / L1 & L2)
- **Managed Disks:** Ausschließlich Managed Disks (keine veralteten Unmanaged Disks auf Storage Accounts) *(L1)*.
- **Disk Encryption:** OS- und Data-Disks verschlüsselt (mind. SSE mit PMK; besser **Encryption at Host** oder **Azure Disk Encryption / CMK**) *(L1/L2)*.
- **Trusted Launch (Gen2 VMs):** Secure Boot & vTPM aktiviert *(L1/L2)*.
- **Endpoint Protection & Defender for Servers:** Microsoft Defender for Endpoint (oder genehmigtes EDR) auf allen VMs aktiv *(L1)*.
- **Update Management / Patching:** Azure Update Manager aktiv, keine kritischen ausstehenden Sicherheitsupdates *(L1)*.
- **VM Extensions Audit:** Nur autorisierte Extensions installiert (keine unbekannten CustomScriptExtensions!) *(L1)*.
- **SSH/Authentifizierung (Linux VMs):** SSH Public Key statt Passwort-Auth (`disablePasswordAuthentication = true`) *(L1)*.
- **Managed Identities:** System-/User-Assigned Managed Identities prüfen → welche Azure RBAC Rollen haben VMs? (Angreifer auf einer VM können via IMDS `169.254.169.254` sofort das Token der Managed Identity abgreifen!).

### Prüfung via UI (Azure Portal)
- *Virtual machines* → VM wählen:
  - *Settings → Disks* (Encryption-Typ prüfen).
  - *Settings → Extensions + applications* (installierte Extensions prüfen).
  - *Settings → Identity* (System/User-Assigned Identity & deren *Azure role assignments*!).
  - *Operations → Updates* (Update Manager / Patch-Status).
  - *Networking → Network settings* (Public IP? NSG?).
- *Microsoft Defender for Cloud → Workload protections → Vulnerability assessment* *(funktioniert mit `Security Reader`!)*.

### Prüfung via CLI (erfordert Azure `Reader`)

```bash
# 1. Alle VMs inkl. Encryption at Host, Trusted Launch, Managed Identity & Password Auth prüfen
az vm list --query "[].{
    Name:name,
    RG:resourceGroup,
    OSType:storageProfile.osDisk.osType,
    EncAtHost:securityProfile.encryptionAtHost,
    SecurityType:securityProfile.securityType,
    IdentityType:identity.type,
    LinuxPwdDisabled:osProfile.linuxConfiguration.disablePasswordAuthentication
}" -o table

# 2. Unverschlüsselte oder Unmanaged Disks prüfen
az disk list --query "[].{Name:name, RG:resourceGroup, EncryptionType:encryption.type, NetworkAccess:networkAccessPolicy}" -o table

# 3. Installierte VM Extensions auflisten
az vm list --query "[].{VM:name, Extensions:resources[].name}" -o json
```

---

## 10.2 Azure App Service & Azure Functions

### Erklärung & Risiko
Web Apps und Functions sind häufig direkt aus dem Internet erreichbar. Typische Fehlkonfigurationen sind aktiviertes **FTP (Klartext)**, veraltete TLS-Versionen (< 1.2), aktiviertes **Remote Debugging**, veraltete Runtimes (EOL-Versionen von Python/.NET/Node/PHP), zu breites **CORS (`*`)** oder fehlende **Managed Identity** (stattdessen hartcodierte Secrets in App Settings).

### Soll-Zustand (CIS Compute / App Service / L1 & L2)
- **HTTPS Only:** `httpsOnly = true` *(L1)*.
- **Minimum TLS Version:** `1.2` (oder `1.3`) *(L1)*.
- **FTP State:** `Disabled` (oder mindestens `FtpsOnly` – niemals `AllAllowed`!) *(L1)*.
- **Remote Debugging:** Deaktiviert (`remoteDebuggingEnabled = false`) *(L1)*.
- **HTTP Version:** HTTP/2 aktiviert (`http20Enabled = true`) *(L1)*.
- **Managed Identity:** Aktiviert für den Zugriff auf Key Vault / SQL / Storage *(L1)*.
- **Latest Runtime Versions:** Aktuelle, supportete Versionen von .NET, Python, Java, Node.js, PHP *(L1)*.
- **App Service Authentication (EasyAuth):** Aktiviert für interne Web-Apps *(L2)*.
- **Client Certificates (mTLS):** Aktiviert, wo fachlich sinnvoll *(L2)*.
- **CORS:** Kein Wildcard `*` in `cors.allowedOrigins` (insb. nicht kombiniert mit `supportCredentials = true`) *(L1)*.
- **Basic Auth Publishing Credentials (SCM/FTP):** Deaktiviert *(L1)*.
- **Public Network Access / VNet Integration:** Interne Apps über Private Endpoints angebunden *(L2)*.

### Prüfung via UI (Azure Portal)
*App Services* (und *Function App*) → App wählen:
1. *Settings → Configuration → General settings:* Stack/Runtime-Version, **FTP state (Disabled/FTPS only)**, **HTTP version (2.0)**, **Remote debugging (Off)**, **Minimum Inbound TLS Version (1.2)**, **Basic Auth Publishing Credentials (Off)**.
2. *Settings → TLS/SSL settings* (bzw. *Configuration*): **HTTPS Only (On)**.
3. *Settings → Authentication:* App Service Authentication prüfen.
4. *Settings → Identity:* Managed Identity & deren Azure RBAC Rollen prüfen.
5. *API → CORS:* Prüfen, ob `*` eingetragen ist.
6. *Settings → Networking:* Access restrictions & Private Endpoints prüfen.

### Prüfung via CLI (erfordert Azure `Reader`)

```bash
# 1. Basis-Sicherheit aller App Services / Function Apps prüfen
az webapp list --query "[].{
    Name:name,
    RG:resourceGroup,
    HTTPSOnly:httpsOnly,
    MinTLS:siteConfig.minTlsVersion,
    FTPS:siteConfig.ftpsState,
    HTTP2:siteConfig.http20Enabled,
    RemoteDebug:siteConfig.remoteDebuggingEnabled,
    Identity:identity.type,
    PublicNet:publicNetworkAccess
}" -o table

# 2. Detailprüfung pro Web App (inkl. CORS & Runtime Stacks)
for row in $(az webapp list --query "[].{name:name, rg:resourceGroup}" -o tsv | tr '\t' ':'); do
  NAME="${row%%:*}"
  RG="${row##*:}"
  echo "=== WebApp: $NAME ($RG) ==="
  az webapp config show --name "$NAME" --resource-group "$RG" \
    --query "{MinTLS:minTlsVersion, FTPS:ftpsState, RemoteDebug:remoteDebuggingEnabled, CORS:cors.allowedOrigins, LinuxFx:linuxFxVersion, NetFx:netFrameworkVersion, Python:pythonVersion, Php:phpVersion}" -o json
done
```

---

## 10.3 Container: Azure Kubernetes Service (AKS) & Azure Container Registry (ACR)

### Erklärung & Risiko
AKS-Cluster mit aktivierten lokalen Admin-Konten, öffentlich erreichbarem Kubernetes API-Server ohne IP-Beschränkung oder fehlendem RBAC/Network-Policy-Schutz sind kritische Ziele für Supply-Chain- und Container-Escape-Angriffe. In der Container Registry (ACR) umgeht der **Admin User** jegliche Entra-ID-Nachvollziehbarkeit.

### Soll-Zustand (CIS AKS / Compute / L1 & L2)
- **AKS:**
  - **Azure RBAC for Kubernetes Authorization** + **Microsoft Entra ID Integration** aktiv *(L1)*.
  - **Local Accounts deaktiviert** (`disableLocalAccounts = true`) *(L1)*.
  - **Private Cluster** (`enablePrivateCluster = true`) oder strikte **Authorized IP Ranges** für den API-Server *(L1/L2)*.
  - **Network Policy** aktiviert (`azure`, `calico` oder `cilium`) *(L1)*.
  - **Azure Policy Add-on for AKS** aktiviert *(L1)*.
  - **Defender for Containers** & Vulnerability Scanning aktiv *(L2)*.
  - **Secrets Store CSI Driver** (Key Vault Integration) statt Plaintext-Kubernetes-Secrets *(L2)*.
- **ACR (Azure Container Registry):**
  - **Admin User deaktiviert** (`adminUserEnabled = false`) *(L1 – häufiges Finding!)*.
  - **Public Network Access:** Deaktiviert (Private Endpoint) *(L2)*.
  - **Anonymous Pull:** Deaktiviert (`anonymousPullEnabled = false`) *(L1)*.
  - **Retention / Quarantine / Vulnerability Scanning (Defender for Containers):** Aktiviert *(L2)*.

### Prüfung via UI (Azure Portal)
- **AKS:** *Kubernetes services* → Cluster → *Settings → Cluster configuration* (Entra ID / Azure RBAC / Local Accounts), *Settings → Networking* (Private cluster, Authorized IP ranges, Network policy), *Settings → Policies*.
- **ACR:** *Container registries* → Registry → *Settings → Access keys* (**Admin user = Disabled**), *Settings → Networking* (Public access / Private endpoints), *Settings → Properties* (Anonymous pull).

### Prüfung via CLI (erfordert Azure `Reader`)

```bash
# 1. AKS Cluster Sicherheitskonfiguration prüfen
az aks list --query "[].{
    Name:name,
    RG:resourceGroup,
    K8sVersion:kubernetesVersion,
    RBAC:enableRbac,
    EntraRBAC:aadProfile.enableAzureRbac,
    DisableLocalAccounts:disableLocalAccounts,
    PrivateCluster:apiServerAccessProfile.enablePrivateCluster,
    AuthorizedIPs:apiServerAccessProfile.authorizedIpRanges,
    NetPolicy:networkProfile.networkPolicy,
    AzurePolicyAddon:addonProfiles.azurepolicy.enabled
}" -o json

# 2. Azure Container Registries (ACR) prüfen
az acr list --query "[].{
    Name:name,
    RG:resourceGroup,
    SKU:sku.name,
    AdminUser:adminUserEnabled,
    AnonymousPull:anonymousPullEnabled,
    PublicNet:publicNetworkAccess
}" -o table
```

---

## 10.4 Analytics Services (CIS Azure Foundations Section 2 – Databricks, Synapse, Data Factory)

### Erklärung & Risiko
Im aktuellen **CIS Microsoft Azure Foundations Benchmark (v5.x/v6.x)** bildet *Section 2: Analytics Services* einen eigenen Schwerpunkt. Analyseplattformen aggregieren oft Daten aus dem gesamten Unternehmen – fehlende Netzwerkisolation oder öffentliche Endpunkte schaffen enorme Risiken.

### Soll-Zustand (CIS Azure Section 2 / L1 & L2)
- **Azure Databricks:** VNet Injection aktiv, No Public IP (`enableNoPublicIp = true`), Private Link, Diagnostic Logging aktiviert, Encryption mit CMK *(L1/L2)*.
- **Azure Synapse Analytics:** Managed Virtual Network aktiviert, Public Network Access deaktiviert, Data Exfiltration Protection aktiviert, Entra-only Auth, Auditing & Defender for SQL aktiv *(L1/L2)*.
- **Azure Data Factory:** Managed Virtual Network, Public Network Access deaktiviert, Key Vault für Linked Service Credentials (keine hartcodierten Passwörter) *(L1/L2)*.

### Prüfung via UI & CLI (Azure Portal / erfordert Azure `Reader`)

```bash
# Analytics-Ressourcen über Azure Resource Graph schnell inventarisieren (erfordert Azure Reader)
az graph query -q "
resources
| where type in~ (
    'microsoft.databricks/workspaces',
    'microsoft.synapse/workspaces',
    'microsoft.datafactory/factories'
)
| project Name=name, Type=type, RG=resourceGroup,
          PublicNet=properties.publicNetworkAccess,
          ManagedVNet=properties.managedVirtualNetwork
" -o table
```

---

## 10.5 Workaround bei reinem Azure `Security Reader` (ohne Azure `Reader`)

Falls du nur Azure `Security Reader` hast, prüfe Compute, App Service, AKS, ACR und Analytics über die Defender-for-Cloud-Assessments:

```bash
# Funktioniert mit reinem Azure Security Reader!
az graph query -q "
securityresources
| where type == 'microsoft.security/assessments'
| where properties.status.code == 'Unhealthy'
| where properties.displayName has_any ('Virtual machine', 'VM', 'disk', 'App Service', 'Function', 'FTPS', 'HTTPS', 'Kubernetes', 'AKS', 'container', 'registry', 'Databricks', 'Synapse', 'endpoint', 'vulnerability', 'update')
| project SubscriptionId=subscriptionId,
          Assessment=tostring(properties.displayName),
          Severity=tostring(properties.metadata.severity),
          ResourceId=tostring(properties.resourceDetails.Id)
| order by Severity desc
" --first 250 -o table
```
