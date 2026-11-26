# Kapitel 5: Kollaboration & Datenfreigabe – SharePoint Online, OneDrive, Teams & Fabric/Power BI

**CIS-Referenz:** CIS Microsoft 365 Foundations Benchmark – *Section 7 (SharePoint & OneDrive)*, *Section 8 (Microsoft Teams)* & *Section 9 (Microsoft Fabric / Power BI)*  
**Primäre Portale:**
- **SharePoint Admin Center:** `https://<tenant>-admin.sharepoint.com`
- **Microsoft Teams Admin Center:** `https://admin.teams.microsoft.com`
- **Microsoft Fabric / Power BI Admin Portal:** `https://app.powerbi.com/admin-portal`

**Erforderliche Rollen & Linux-CLI-Status:**
- **SharePoint Online:** `Global Reader` liest alle Tenant-Einstellungen in der **UI** und **100 % nativ unter Linux via Graph REST API (`/v1.0/admin/sharepoint/settings`)** ✅ *(kein `Get-SPOTenant` / kein PowerShell nötig!)*.
- **Microsoft Teams:** `Global Reader` liest alle Sicherheits-Policies ✅. Da Teams-Tenant-Policies (`CsTenantFederationConfiguration`, `CsTeamsMeetingPolicy` etc.) keine Graph-REST-API besitzen, erfolgt die CLI-Abfrage unter Linux via nativem **`pwsh` (`MicrosoftTeams`)** (direkt aus Bash aufrufbar).
- **Microsoft Fabric / Power BI:** REST-API-Aufruf per **`az account get-access-token` + `curl` + `jq`** möglich – **Achtung:** Fabric Tenant Settings erfordern meist **Fabric Administrator** ⚠️ (mit reinem `Global Reader` ggf. per Kunden-Screenshare prüfen).

---

## 5.1 SharePoint Online & OneDrive (CIS Section 7)

### Erklärung & Risiko
Standardmäßig erlauben SharePoint und OneDrive anonyme „Anyone with the link“-Freigaben, unbefristete Gastlinks und das Herunterladen von Dateien auf private (unmanaged) Endgeräte. Fehlkonfigurationen hier führen sehr schnell zu unbemerktem Datenabfluss (Data Exfiltration).

### Soll-Zustand (CIS 7.2.x – 7.3.x / L1 & L2)
- **Externes Sharing-Level (SharePoint & OneDrive):** Mindestens auf *Existing guests* oder *New and existing guests* beschränkt – **kein** „Anyone“ (anonyme Links) *(L1)*.
- **Domain-Einschränkungen:** Externes Teilen auf erlaubte Partner-Domains beschränkt oder Freemail-Domains blockiert *(L2)*.
- **Standard-Freigabelink:** Typ auf **Specific people** (oder *Only people in your organization*), Berechtigung auf **View** (nicht *Edit*) *(L1)*.
- **Ablaufdatum für Gastzugriffe & Links:** Konfiguriert (z. B. 30 Tage) *(L1/L2)*.
- **Gäste dürfen nicht weiter teilen:** `isResharingByExternalUsersEnabled == false` *(L1)*.
- **Microsoft Entra B2B Integration:** Aktiviert *(L1)*.
- **Legacy Authentication (SPO):** Blockiert (`isLegacyAuthProtocolsEnabled == false`) *(L1)*.
- **Unmanaged Devices:** Zugriff eingeschränkt (Web-only / Block Download oder blockiert via CA App Control) *(L2)*.
- **OneDrive Sync-Beschränkung:** Nur auf domänengejointen / verwalteten Geräten (`isUnmanagedSyncClientForTenantRestricted == true`) *(L2)*.
- **Idle Session Sign-out:** Aktiviert (z. B. 1–3 Stunden) *(L1)*.
- **Custom Scripts:** Deaktiviert *(L1)*.

### Prüfung via UI (SharePoint Admin Center)
1. **Sharing:** `SharePoint Admin Center` → *Policies → Sharing* (SharePoint & OneDrive Schieberegler, Domain-Beschränkung, Resharing, Guest Access Expiration, Standard-Link-Typ & Berechtigung „View“).
2. **Access Control:** *Policies → Access control* (*Unmanaged devices*, *Idle session sign-out*, *Network location*, *Apps that don't use modern authentication = Block access*).
3. **OneDrive Sync:** *Settings → OneDrive → Sync* → „Allow syncing only on computers joined to specific domains“.
4. **Site-Ausnahmen:** *Sites → Active sites* → Spalte **External sharing** sortieren.

### Prüfung via Linux CLI (`az rest` / `m365` + `jq` – 100 % nativ unter Linux!)

```bash
# 1. SharePoint & OneDrive Tenant Settings über Microsoft Graph REST API
#    Funktioniert mit Global Reader OHNE SharePoint Admin und OHNE PowerShell!
#    (Bei 403 mit az rest -> 'm365 request --url ... --output json' nutzen)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/admin/sharepoint/settings" -o json \
| jq '{
    sharingCapability: .sharingCapability,
    sharingDomainRestrictionMode: .sharingDomainRestrictionMode,
    sharingAllowedDomainList: .sharingAllowedDomainList,
    sharingBlockedDomainList: .sharingBlockedDomainList,
    resharingByExternalUsers: .isResharingByExternalUsersEnabled,
    legacyAuthEnabled: .isLegacyAuthProtocolsEnabled,
    macSyncEnabled: .isMacSyncAppEnabled,
    unmanagedSyncRestricted: .isUnmanagedSyncClientForTenantRestricted,
    allowedSyncDomainGuids: .allowedDomainGuidsForSyncClient,
    idleSessionSignOut: .idleSessionSignOut
  }'

# 2. Alternative mit CLI for Microsoft 365 (m365) auf Linux:
m365 request \
  --url "https://graph.microsoft.com/v1.0/admin/sharepoint/settings" \
  --accept "application/json" --output json | jq .
```

---

## 5.2 Microsoft Teams (CIS Section 8)

### Erklärung & Risiko
Offene Teams-Federation („Allow all external domains“ + „External users with Teams accounts not managed by an organization“) ist einer der meistgenutzten Phishing- und Social-Engineering-Kanäle gegen Unternehmen (Angreifer schreiben Mitarbeiter direkt per Teams-Chat als „IT-Support“ an).

### Soll-Zustand (CIS 8.1.x – 8.6.x / L1 & L2)
- **Externe Kommunikation / Federation:** Nicht „Allow all external domains“ → besser **Allow only specific external domains** *(L2)*; **Unmanaged Teams-Benutzer** (`AllowTeamsConsumer = false`, `AllowTeamsConsumerInbound = false`) und **Skype Consumer** (`AllowPublicUsers = false`) deaktiviert *(L1 – extrem wichtig!)*.
- **Drittanbieter-Cloud-Speicher:** Dropbox, Box, Google Drive, ShareFile, Egnyte deaktiviert *(L1)*.
- **Kanal-E-Mail-Integration:** Deaktiviert (`AllowEmailIntoChannel = false`) oder eingeschränkt *(L2)*.
- **App Permission Policies:** Drittanbieter- und Custom Apps nicht pauschal für alle freigegeben *(L1)*.
- **Meeting Policies (`Global`):**
  - `AllowAnonymousUsersToJoinMeeting = false` & `AllowAnonymousUsersToStartMeeting = false` *(L1)*.
  - `AutoAdmittedUsers` maximal *People in my org* (niemals `Everyone`) *(L1)*.
  - `AllowPSTNUsersToBypassLobby = false` *(L1)*.
  - `AllowExternalParticipantGiveRequestControl = false` *(L1)*.
  - `DesignatedPresenterRoleMode` eingeschränkt *(L2)*, `MeetingChatEnabledType = EnabledExceptAnonymous` *(L2)*, `AllowSecurityEndUserReporting = true` *(L1)*.

### Prüfung via UI (Microsoft Teams Admin Center – `admin.teams.microsoft.com`)
1. **External Access:** *Users → External access* (Federation, Unmanaged Teams Users, Skype Users).
2. **Guest Access:** *Users → Guest access*.
3. **Teams Settings:** *Teams → Teams settings* (*Files* & *Email integration*).
4. **Meeting Policies:** *Meetings → Meeting policies → Global (Org-wide default)* (und Custom Policies).
5. **App Policies:** *Teams apps → Permission policies* & *Manage apps → Org-wide app settings*.

### Prüfung via Linux CLI

```bash
# 1. Teams-Inventar (inkl. Public vs. Private Teams) nativ via Linux CLI (az rest + jq):
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/groups?\$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&\$select=displayName,visibility,createdDateTime&\$top=999" \
  --query "value[].{Team:displayName, Visibility:visibility, Created:createdDateTime}" -o table

# 2. Teams Tenant-Policies (Federation, Client Config, Meetings, Messaging, Apps)
#    [Microsoft-Limit: keine Graph-REST-API -> Aufruf direkt aus Linux-Bash über pwsh:]
pwsh -NoLogo -Command '
  Connect-MicrosoftTeams -UseDeviceAuthentication -TenantId "<TENANT_ID>" | Out-Null

  Write-Host "`n=== External Access / Federation ==="
  Get-CsTenantFederationConfiguration | Select-Object AllowFederatedUsers, AllowedDomains, AllowPublicUsers, AllowTeamsConsumer, AllowTeamsConsumerInbound | Format-List

  Write-Host "=== Client Config (Cloud Storage & Channel Email) ==="
  Get-CsTeamsClientConfiguration | Select-Object AllowDropBox, AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte, AllowEmailIntoChannel, RestrictedSenderList | Format-List

  Write-Host "=== Meeting Policies ==="
  Get-CsTeamsMeetingPolicy | Select-Object Identity, AllowAnonymousUsersToJoinMeeting, AllowAnonymousUsersToStartMeeting, AutoAdmittedUsers, AllowPSTNUsersToBypassLobby, AllowExternalParticipantGiveRequestControl, DesignatedPresenterRoleMode, MeetingChatEnabledType, AllowCloudRecording | Format-List

  Write-Host "=== Messaging Policy (Global) & App Permission Policies ==="
  Get-CsTeamsMessagingPolicy -Identity Global | Select-Object AllowUserChat, AllowUrlPreview, AllowSecurityEndUserReporting | Format-List
  Get-CsTeamsAppPermissionPolicy | Select-Object Identity, DefaultCatalogAppsType, GlobalCatalogAppsType, PrivateCatalogAppsType | Format-Table -AutoSize

  Disconnect-MicrosoftTeams
'
```

---

## 5.3 Microsoft Fabric / Power BI (CIS Section 9)

### Erklärung & Risiko
Power BI / Microsoft Fabric verarbeitet oft hochsensible Finanz-, HR- und Geschäftsdaten. **„Publish to web“** macht Berichte **vollständig öffentlich ohne Authentifizierung im Internet** auffindbar!

### Soll-Zustand (CIS 9.1.x / L1 & L2)
- **Publish to web:** Deaktiviert (oder strikt auf Sicherheitsgruppe beschränkt) *(L1 – kritisch!)*.
- **Guest users / External invites / Shareable links / External data sharing:** Deaktiviert oder restriktiv eingegrenzt *(L1)*.
- **R and Python visuals:** Deaktiviert *(L2)*.
- **Apply sensitivity labels to content:** Aktiviert *(L1)*.
- **Service principals (Fabric APIs / Workspaces):** Nur für dedizierte Sicherheitsgruppe *(L1)*.
- **Block ResourceKey Authentication:** Aktiviert *(L1)*.

### Prüfung via UI (Microsoft Fabric Admin Portal – `https://app.powerbi.com/admin-portal`)
- `Fabric Admin Portal` → **Tenant settings** (*Export and sharing settings*, *Information protection*, *Developer settings*, *R and Python visuals*, *Security*).

### Prüfung via Linux CLI (`az` + `curl` + `jq`)

```bash
# Hinweis: Erfordert Fabric Administrator (mit reinem Global Reader liefert die API oft 401/403!)
FABRIC_TOKEN=$(az account get-access-token --resource "https://api.fabric.microsoft.com" --query accessToken -o tsv)

curl -sS -H "Authorization: Bearer ${FABRIC_TOKEN}" \
  "https://api.fabric.microsoft.com/v1/admin/tenantsettings" \
| jq '.tenantSettings[] | select(.settingName | test("PublishToWeb|Guest|External|Sensitivity|ServicePrincipal|ResourceKey|Visual"; "i")) | {name: .settingName, title: .title, enabled: .enabled, groupType: .enabledSecurityGroups}'
```

> [!TIP]
> **Praxis-Hinweis:** Wenn `Global Reader` im Fabric Admin Portal / an der Fabric-API `403 Forbidden` erhält, dokumentiere das als **Berechtigungsabgrenzung** und prüfe die 6 kritischen Schalter in einem kurzen Screenshare gemeinsam mit dem Kunden-Admin.
