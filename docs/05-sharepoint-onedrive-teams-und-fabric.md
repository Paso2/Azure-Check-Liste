# Kapitel 5: Kollaboration & Datenfreigabe – SharePoint Online, OneDrive, Teams & Fabric/Power BI

**CIS-Referenz:** CIS Microsoft 365 Foundations Benchmark – *Section 7 (SharePoint & OneDrive)*, *Section 8 (Microsoft Teams)* & *Section 9 (Microsoft Fabric / Power BI)*  
**Primäre Portale:**
- **SharePoint Admin Center:** `https://<tenant>-admin.sharepoint.com`
- **Microsoft Teams Admin Center:** `https://admin.teams.microsoft.com`
- **Microsoft Fabric / Power BI Admin Portal:** `https://app.powerbi.com/admin-portal`

**Erforderliche Rollen & Grenzen:**
- **SharePoint Online:** `Global Reader` kann alle Einstellungen in der **UI** und über die **Microsoft Graph API** (`/v1.0/admin/sharepoint/settings`) lesen ✅. **Achtung:** Das klassische SharePoint-PowerShell-Cmdlet `Get-SPOTenant` schlägt mit reinem `Global Reader` i. d. R. fehl (erfordert *SharePoint Administrator*)!
- **Microsoft Teams:** `Global Reader` hat Read-Only-Zugriff in UI & Teams PowerShell ✅ *(ohne Analytics/Reports & App-Katalog-Details)*.
- **Microsoft Fabric / Power BI:** `Global Reader` hat im Fabric Admin Portal oft **keinen** vollständigen Zugriff auf die *Tenant Settings* ⚠️ → entweder temporär *Fabric Administrator* (oder Read-Only-Screenshot-Review / Live-Screenshare mit dem Kunden-Admin).

---

## 5.1 SharePoint Online & OneDrive (CIS Section 7)

### Erklärung & Risiko
Standardmäßig erlauben SharePoint und OneDrive anonyme „Anyone with the link“-Freigaben, unbefristete Gastlinks und das Herunterladen von Dateien auf private (unmanaged) Endgeräte. Fehlkonfigurationen hier führen sehr schnell zu unbemerktem Datenabfluss (Data Exfiltration).

### Soll-Zustand (CIS 7.2.x – 7.3.x / L1 & L2)
- **Externes Sharing-Level (SharePoint & OneDrive):** Mindestens auf *Existing guests* oder *New and existing guests* beschränkt – **kein** „Anyone“ (anonyme Links) *(L1)*. *(Für OneDrive idealerweise noch restriktiver als SharePoint.)*
- **Domain-Einschränkungen:** Externes Teilen auf erlaubte Partner-Domains beschränkt oder Freemail-Domains blockiert *(L2)*.
- **Standard-Freigabelink:** Typ auf **Specific people** (oder *Only people in your organization*), Berechtigung auf **View** (nicht *Edit*) *(L1)*.
- **Ablaufdatum für Gastzugriffe & Links:** Konfiguriert (z. B. 30 Tage) *(L1/L2)*.
- **Gäste dürfen nicht weiter teilen:** „Allow guests to share items they don't own“ **deaktiviert** *(L1)*.
- **Microsoft Entra B2B Integration:** Aktiviert (Gäste erhalten echte Entra-Identitäten inkl. Conditional Access & MFA statt reinem E-Mail-One-Time-Passcode ohne CA) *(L1)*.
- **Legacy Authentication (SPO):** Blockiert (`LegacyAuthProtocolsEnabled = $false`) *(L1)*.
- **Unmanaged Devices:** Zugriff auf SharePoint/OneDrive von nicht verwalteten Geräten eingeschränkt (Web-only / Block Download oder komplett blockiert via Conditional Access App Control) *(L2)*.
- **OneDrive Sync-Beschränkung:** Synchronisation nur auf domänengejointen / Intune-compliant Geräten erlaubt (`AllowedDomainGuidsForSyncClient`) *(L2)*.
- **Idle Session Sign-out:** Aktiviert (z. B. 1–3 Stunden) *(L1)*.
- **Custom Scripts:** Deaktiviert (`DenyAddAndCustomizePages`) *(L1)*.

### Prüfung via UI (SharePoint Admin Center)
1. **Sharing:** `SharePoint Admin Center` → *Policies → Sharing*:
   - Schieberegler für **SharePoint** und **OneDrive** prüfen.
   - *More external sharing settings* (Domain-Beschränkung, Gäste dürfen nicht weiter teilen, Guest Access Expiration).
   - *File and folder links* (Standard-Link-Typ & Berechtigung „View“).
2. **Access Control:** *Policies → Access control*:
   - *Unmanaged devices*
   - *Idle session sign-out*
   - *Network location*
   - *Apps that don't use modern authentication* (muss auf **Block access** stehen!).
3. **OneDrive Sync:** *Settings → OneDrive → Sync* → „Allow syncing only on computers joined to specific domains“ prüfen.
4. **Site-Ausnahmen prüfen:** *Sites → Active sites* → Spalte **External sharing** sortieren (auch bei restriktivem Tenant-Standard können einzelne Alt-Sites abweichen).

### Prüfung via CLI / PowerShell (funktioniert mit `Global Reader` via Microsoft Graph!)

```powershell
# SharePoint Tenant Settings über Microsoft Graph API abfragen (benötigt SharePointTenantSettings.Read.All)
# Funktioniert mit Global Reader OHNE SharePoint Admin!
Get-MgAdminSharepointSetting | Select-Object `
    SharingCapability,
    SharingDomainRestrictionMode,
    SharingAllowedDomainList,
    SharingBlockedDomainList,
    IsResharingByExternalUsersEnabled,
    IsLegacyAuthProtocolsEnabled,
    IsMacSyncAppEnabled,
    IsUnmanagedSyncClientForTenantRestricted,
    AllowedDomainGuidsForSyncClient,
    IdleSessionSignOut,
    PersonalSiteDefaultStorageLimitInMB | Format-List
```

```bash
# Alternative über Azure CLI (az rest → Microsoft Graph)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/admin/sharepoint/settings" \
  -o json
```

---

## 5.2 Microsoft Teams (CIS Section 8)

### Erklärung & Risiko
Offene Teams-Federation („Allow all external domains“ + „External users with Teams accounts not managed by an organization“) ist einer der meistgenutzten Phishing- und Social-Engineering-Kanäle gegen Unternehmen (Angreifer schreiben Mitarbeiter direkt per Teams-Chat als „IT-Support“ an und verschicken bösartige Links oder Quick-Assist-Anfragen!).

### Soll-Zustand (CIS 8.1.x – 8.6.x / L1 & L2)
- **Externe Kommunikation / Federation (External Access):**
  - **Nicht** auf „Allow all external domains“ → besser **Allow only specific external domains** (Whitelist) *(L2)* oder zumindest **Block domains**.
  - **Unmanaged Teams-Benutzer** („People in my organization can communicate with Teams users whose accounts aren't managed by an organization“): **Deaktiviert** (`AllowTeamsConsumer = $false`, `AllowTeamsConsumerInbound = $false`) *(L1 – extrem wichtig!)*.
  - **Skype-Consumer-Kommunikation:** Deaktiviert (`AllowPublicUsers = $false`) *(L1)*.
- **Drittanbieter-Cloud-Speicher (Teams Settings):** Dropbox, Box, Google Drive, Egnyte, Citrix Files deaktiviert *(L1)*.
- **Kanal-E-Mail-Integration:** Deaktiviert (`AllowEmailIntoChannel = $false`) oder auf sichere Absender-Domains begrenzt *(L2)*.
- **App Permission Policies:** Drittanbieter-Apps und Custom Apps nicht pauschal für alle Benutzer freigeben (`ThirdPartyAppsDefaultCatalogAppsType`, `PrivateCatalogAppsType`) *(L1)*.
- **Meeting Policies (`Global`):**
  - **Anonyme Benutzer können Meetings beitreten:** Deaktiviert (`AllowAnonymousUsersToJoinMeeting = $false`) oder nur in dedizierter Policy für Vertrieb/HR erlaubt *(L1)*.
  - **Anonyme Benutzer können Meetings starten:** Deaktiviert (`AllowAnonymousUsersToStartMeeting = $false`) *(L1)*.
  - **Lobby-Bypass (`AutoAdmittedUsers`):** Maximal *People in my org* (oder *Invited users*), **niemals** `Everyone` *(L1)*.
  - **Einwahl-Nutzer umgehen Lobby:** Deaktiviert (`AllowPSTNUsersToBypassLobby = $false`) *(L1)*.
  - **Externe Teilnehmer dürfen Steuerung anfordern/geben:** Deaktiviert (`AllowExternalParticipantGiveRequestControl = $false`) *(L1)*.
  - **Wer darf präsentieren (`DesignatedPresenterRoleMode`):** Eingeschränkt (nicht `EveryoneUserOverride`) *(L2)*.
  - **Meeting-Chat für anonyme/externe Nutzer:** Eingeschränkt (`MeetingChatEnabledType = EnabledExceptAnonymous`) *(L2)*.
  - **Cloud-Aufzeichnung:** Standardmäßig deaktiviert oder bewusst geregelt (`AllowCloudRecording`) *(L2)*.
  - **Report a security concern** aktiviert *(L1)*.

### Prüfung via UI (Microsoft Teams Admin Center – `admin.teams.microsoft.com`)
1. **External Access:** *Users → External access* (Federation-Modus, Unmanaged Teams Users, Skype Users).
2. **Guest Access:** *Users → Guest access*.
3. **Teams Settings (Dateispeicher & Kanal-E-Mail):** *Teams → Teams settings* (*Files* & *Email integration*).
4. **Meeting Policies:** *Meetings → Meeting policies → Global (Org-wide default)* (und alle Custom Policies prüfen!).
5. **App Policies:** *Teams apps → Permission policies* & *Manage apps → Org-wide app settings*.

### Prüfung via CLI / PowerShell (MicrosoftTeams PowerShell – funktioniert mit `Global Reader`!)

```powershell
# 1. External Access / Federation Configuration
Get-CsTenantFederationConfiguration | Select-Object `
    AllowFederatedUsers,
    AllowedDomains,
    AllowPublicUsers,
    AllowTeamsConsumer,
    AllowTeamsConsumerInbound | Format-List

# 2. Teams Client Configuration (Cloud-Speicher & Kanal-E-Mail)
Get-CsTeamsClientConfiguration | Select-Object `
    AllowDropBox, AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte,
    AllowEmailIntoChannel, RestrictedSenderList | Format-List

# 3. Meeting Policies (Global & Custom)
Get-CsTeamsMeetingPolicy | Select-Object `
    Identity,
    AllowAnonymousUsersToJoinMeeting,
    AllowAnonymousUsersToStartMeeting,
    AutoAdmittedUsers,
    AllowPSTNUsersToBypassLobby,
    AllowExternalParticipantGiveRequestControl,
    DesignatedPresenterRoleMode,
    MeetingChatEnabledType,
    AllowCloudRecording,
    AllowIPVideo | Format-List

# 4. Messaging Policy (Report security concern / External Chat)
Get-CsTeamsMessagingPolicy -Identity Global | Select-Object `
    AllowUserChat, AllowUrlPreview, AllowSecurityEndUserReporting | Format-List

# 5. App Permission Policies
Get-CsTeamsAppPermissionPolicy | Select-Object `
    Identity, DefaultCatalogAppsType, GlobalCatalogAppsType, PrivateCatalogAppsType | Format-Table -AutoSize
```

---

## 5.3 Microsoft Fabric / Power BI (CIS Section 9)

### Erklärung & Risiko
Power BI / Microsoft Fabric verarbeitet oft hochsensible Finanz-, HR- und Geschäftsdaten. Die Funktion **„Publish to web“** macht Berichte **vollständig öffentlich ohne Authentifizierung im Internet** auffindbar! Zudem erlauben unkontrollierte Gast- und Service-Principal-Einstellungen unbemerkte Datenabzüge.

### Soll-Zustand (CIS 9.1.x / L1 & L2)
- **Publish to web:** Deaktiviert (oder strikt auf eine explizite Sicherheitsgruppe beschränkt) *(L1 – kritisch!)*.
- **Allow Microsoft Entra guest users to access Fabric:** Deaktiviert oder auf Sicherheitsgruppe eingeschränkt *(L1)*.
- **Invite external users to your organization:** Deaktiviert *(L1)*.
- **Guest users can browse and access Fabric content / Shareable links to grant access to everyone:** Deaktiviert *(L1)*.
- **Allow external data sharing:** Deaktiviert *(L1)*.
- **Interact with and share R and Python visuals:** Deaktiviert *(L2)*.
- **Apply sensitivity labels to content:** Aktiviert *(L1)*.
- **Service principals can use Fabric APIs / Create workspaces:** Eingeschränkt auf dedizierte Sicherheitsgruppe *(L1)*.
- **Block ResourceKey Authentication:** Aktiviert *(L1)*.

### Prüfung via UI (Microsoft Fabric Admin Portal – `https://app.powerbi.com/admin-portal`)
- `Fabric Admin Portal` → **Tenant settings**:
  - Abschnitt *Export and sharing settings* (Publish to web, Guest access, External sharing, Shareable links)
  - Abschnitt *Information protection* (Sensitivity labels)
  - Abschnitt *Developer settings* (Service principals)
  - Abschnitt *R and Python visuals*
  - Abschnitt *Security* (Block ResourceKey Authentication)

### Prüfung via CLI / PowerShell (nur mit Fabric Admin / API-Berechtigung)

```powershell
# Hinweis: Erfordert Fabric Administrator oder Service Principal mit Tenant.Read.All (Power BI API)
# Mit reinem Global Reader gibt dieser Aufruf häufig 401/403 zurück → dann per Kunden-Screenshot prüfen!
# Connect-PowerBIServiceAccount
# Invoke-PowerBIRestMethod -Url "https://api.fabric.microsoft.com/v1/admin/tenantsettings" -Method Get
```

> [!TIP]
> **Praxis-Hinweis für das Assessment:** Wenn du im Fabric Admin Portal (`app.powerbi.com/admin-portal`) mit `Global Reader` keine *Tenant settings* siehst, dokumentiere das transparent als **Scope-/Berechtigungsabgrenzung** und bitte den Kunden in einem 10-minütigen Screenshare, die 6 kritischen Schalter (*Publish to web*, *Guest access*, *External sharing*, *Sensitivity labels*, *Service principals*, *ResourceKey Auth*) zu zeigen.
