# Kapitel 2: Microsoft Entra ID – Identitäten, Authentifizierung & Zugriffskontrolle

**CIS-Referenz:** CIS Microsoft 365 Foundations Benchmark – *Section 5: Microsoft Entra Admin Center* (L1 & L2) sowie Identity-Grundlagen für Azure  
**Primäres Portal:** **Microsoft Entra Admin Center** (`https://entra.microsoft.com`) *(Hinweis: Alle Einstellungen sind auch im Azure Portal unter „Microsoft Entra ID“ sichtbar, das Entra Admin Center ist jedoch das dedizierte Zielportal.)*  
**Erforderliche Rollen:** Entra `Global Reader` + Entra `Security Reader` (vollständig prüfbar ✅)

> [!IMPORTANT]
> **Warum zuerst Entra ID?**  
> Microsoft Entra ID ist die gemeinsame Identitäts-Control-Plane für **sowohl Microsoft 365 als auch Microsoft Azure**. Eine Schwachstelle in Conditional Access, eine überprivilegierte App-Registrierung oder ungeschützte Global-Admin-Konten gefährden gleichzeitig E-Mails, SharePoint-Daten und produktive Azure-Subscriptions.

---

## 2.1 Security Defaults vs. Conditional Access Policies

### Erklärung & Risiko
Ohne Conditional Access (CA) oder Security Defaults greifen keine tenantweiten MFA- oder Legacy-Auth-Sperren. Security Defaults sind nur für kleinere Tenants ohne Entra ID P1 gedacht; in Enterprise-Umgebungen (mit P1/P2) müssen granulare **Conditional Access Policies** aktiviert sein – und Security Defaults entsprechend deaktiviert.

### Soll-Zustand (CIS 5.2.2.x / L1 & L2)
- Entweder **Security Defaults aktiviert** (nur bei fehlender P1-Lizenz) **oder** ein vollständiges **Conditional Access Regelwerk** im Status `enabled` (nicht nur `enabledForReportingButNotEnforced`!).
- Mindest-Policies (CIS L1/L2):
  1. **MFA für alle administrativen Rollen** *(L1)* – idealerweise **Phishing-resistant MFA** (FIDO2 / Windows Hello for Business / Zertifikat) *(L2)*.
  2. **MFA für alle Benutzer** *(L1)* (inkl. Gäste!).
  3. **Legacy Authentication blockieren** (Exchange ActiveSync & Other Clients) *(L1)*.
  4. **Sign-in Risk Policy** (High/Medium Risk → MFA oder Block) *(L1, erfordert Entra ID P2)*.
  5. **User Risk Policy** (High Risk → Password Change + MFA oder Block) *(L1, erfordert Entra ID P2)*.
  6. **Managed / Compliant Devices** für sensible Apps & Admin-Portale *(L2)*.
  7. **Zugriff auf Admin-Portale** (Azure Portal, Entra, M365 Admin) einschränken *(L2)*.
  8. **Session Controls** (Sign-in Frequency für Admins, Persistent Browser Session deaktiviert auf unmanaged Devices, Token Protection falls lizenziert) *(L2)*.
- **Exclusions-Audit (extrem wichtig!):** Prüfe jede CA-Policy auf ausgeschlossene Benutzer, Gruppen, Rollen und Apps. Einzig legitime Ausnahmen sind i. d. R. die **1–2 dokumentierten Break-Glass-Konten** (und ggf. der Entra Connect Sync-Account).

### Prüfung via UI (Entra Admin Center)
1. **Security Defaults:** `Entra Admin Center` → *Identity → Overview → Properties → Manage security defaults*.
2. **Conditional Access:** `Entra Admin Center` → *Protection → Conditional Access → Policies*.
   - Prüfe Status (`On` vs. `Report-only` vs. `Off`).
   - Öffne jede Policy und kontrolliere **Users → Exclude**, **Target resources → Exclude**, **Conditions (Client apps)** und **Grant / Session Controls**.
3. **Named Locations:** *Protection → Conditional Access → Named locations* → prüfen, ob „Trusted IPs“ MFA umgehen (Riskant bei großen NAT/VPN-Bereichen!).

### Prüfung via CLI / PowerShell

```powershell
# 1. Security Defaults Status prüfen
Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Select-Object IsEnabled

# 2. Alle Conditional Access Policies inkl. Status & Exclusions ausgeben
Get-MgIdentityConditionalAccessPolicy -All | ForEach-Object {
    [PSCustomObject]@{
        Name                 = $_.DisplayName
        State                = $_.State
        IncludeUsers         = ($_.Conditions.Users.IncludeUsers -join ", ")
        ExcludeUsers         = ($_.Conditions.Users.ExcludeUsers -join ", ")
        ExcludeGroups        = ($_.Conditions.Users.ExcludeGroups -join ", ")
        ExcludeRoles         = ($_.Conditions.Users.ExcludeRoles -join ", ")
        ClientAppTypes       = ($_.Conditions.ClientAppTypes -join ", ")
        GrantControls        = ($_.GrantControls.BuiltInControls -join ", ")
        AuthStrength         = $_.GrantControls.AuthenticationStrength.DisplayName
        SignInRiskLevels     = ($_.Conditions.SignInRiskLevels -join ", ")
        UserRiskLevels       = ($_.Conditions.UserRiskLevels -join ", ")
    }
} | Format-Table -AutoSize

# 3. Vollständigen JSON-Export für Evidenz speichern
Get-MgIdentityConditionalAccessPolicy -All | ConvertTo-Json -Depth 10 | Out-File "ca-policies.json"
```

```bash
# Alternative über Azure CLI (az rest → Microsoft Graph, kein separates MgGraph-Modul nötig)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[].{Name:displayName, State:state, ExcludeUsers:conditions.users.excludeUsers, Grant:grantControls.builtInControls}" \
  -o table
```

---

## 2.2 Privilegierte Rollen, Global Admins, Break-Glass-Konten & PIM

### Erklärung & Risiko
Übermäßige, dauerhaft zugewiesene oder aus dem On-Premises-AD synchronisierte Admin-Konten sind der Hauptvektor für vollständige Tenant-Kompromittierungen (inkl. Hybrid-Lateral-Movement von On-Prem nach Cloud).

### Soll-Zustand (CIS 5.1.x / 5.3.x / L1 & L2)
- **Anzahl Global Administrators:** Mindestens **2**, höchstens **4** (inkl. Break-Glass-Konten) *(L1)*.
- **Dedizierte Cloud-only Admin-Konten:** Keine produktive E-Mail/M365-Lizenz auf Admin-Konten, **keine** Synchronisation aus On-Premises AD (`OnPremisesSyncEnabled -ne $true`) *(L1)*.
- **Notfallkonten (Break-Glass):** 2 dedizierte Cloud-only-Konten (`*.onmicrosoft.com`), starke Phishing-resistente Authentifizierung (z. B. FIDO2-Hardware-Keys im Tresor), ausgeschlossen von fehleranfälligen CA-Policies, aber mit **Alerting bei jedem Login** überwacht *(L1)*.
- **Privileged Identity Management (PIM – erfordert Entra ID P2):**
  - Privilegierte Rollen (Global Admin, Privileged Role Admin, Security Admin, Exchange/SharePoint/Application Admin etc.) sind **Eligible**, nicht dauerhaft **Active** *(L2)*.
  - Aktivierung erfordert **MFA**, **Begründung (Justification)**, zeitliche Begrenzung (z. B. max. 1–8 Stunden) und für kritische Rollen **Genehmigung (Approval)** *(L2)*.
  - Regelmäßige **Access Reviews** für privilegierte Rollen eingerichtet *(L2)*.

### Prüfung via UI (Entra Admin Center)
1. **Aktive Rollenzuweisungen:** `Entra Admin Center` → *Identity → Roles & admins → Roles & admins* → *Global Administrator* (und weitere hochprivilegierte Rollen) anklicken → Reiter *Assignments*.
2. **PIM (falls P2 lizenziert):** `Entra Admin Center` → *Identity Governance → Privileged Identity Management → Microsoft Entra roles*:
   - *Assignments* → Verhältnis **Eligible** vs. **Active** prüfen.
   - *Settings* → je Rolle (insb. *Global Administrator*, *Privileged Role Administrator*, *Application Administrator*) Aktivierungsdauer, MFA-Pflicht, Approval & Benachrichtigungen prüfen.
   - *Access reviews* → aktive periodische Reviews für privilegierte Rollen prüfen.

### Prüfung via CLI / PowerShell

```powershell
# 1. Alle aktiven (dauerhaften) Rollenzuweisungen auflisten
$roles = Get-MgDirectoryRole -All
foreach ($role in $roles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
    foreach ($m in $members) {
        $u = $m.AdditionalProperties
        [PSCustomObject]@{
            RoleName      = $role.DisplayName
            MemberName    = $u.displayName
            UPN           = $u.userPrincipalName
            ObjectType    = $u.'@odata.type'
            OnPremSynced  = $u.onPremisesSyncEnabled
            AccountEnabled= $u.accountEnabled
        }
    }
} | Sort-Object RoleName | Format-Table -AutoSize

# 2. PIM Eligible vs. Active Schedule Instances (erfordert Entra ID P2 + RoleManagement.Read.Directory)
Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All | Select-Object RoleDefinitionId, PrincipalId, StartDateTime, EndDateTime
Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All | Select-Object RoleDefinitionId, PrincipalId, AssignmentType, StartDateTime, EndDateTime
```

```bash
# Global Administrators schnell per az rest prüfen
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/directoryRoles" \
  --query "value[?displayName=='Global Administrator'].id" -o tsv | \
xargs -I{} az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/directoryRoles/{}/members" \
  --query "value[].{Name:displayName, UPN:userPrincipalName, Synced:onPremisesSyncEnabled}" -o table
```

---

## 2.3 Authentifizierungsmethoden, MFA-Härtung & Passwortschutz

### Erklärung & Risiko
Schwache MFA-Methoden wie **SMS** oder **Voice Call** sind anfällig für SIM-Swapping und Social Engineering. Fehlende Number-Matching-/Kontext-Informationen bei Push-Benachrichtigungen ermöglichen **MFA-Fatigue-Angriffe**. Schwache Passwörter ohne Smart Lockout begünstigen Password Spraying.

### Soll-Zustand (CIS 5.2.3.x / L1 & L2)
- **Authentication Methods Policy Migration:** Migration abgeschlossen (`migrationComplete`) *(L1)*.
- **Microsoft Authenticator:** Number Matching, App-Kontext & Standortanzeige aktiv *(L1)*.
- **FIDO2 / Passkeys** aktiviert (mind. für Admins) *(L2)*.
- **SMS & Voice Call** als MFA-Methode deaktiviert oder strikt auf Ausnahmegruppen beschränkt *(L1/L2)*.
- **System-preferred MFA** aktiviert *(L1)*.
- **MFA-Registrierungsstatus:** Alle aktiven Benutzer (100 % der Admins, idealerweise 100 % aller Nutzer) sind für MFA registriert *(L1)*.
- **Entra Password Protection:** Smart Lockout konfiguriert (z. B. Threshold ≤ 10, Lockout Duration ≥ 60 Sek.), Custom Banned Password List aktiviert (Firmenname, Standorte, Produkte), bei Hybrid-AD auch **On-Premises Password Protection Proxy/DC Agent** aktiv *(L1/L2)*.
- **Self-Service Password Reset (SSPR):** Wenn aktiviert, mindestens **2 Authentifizierungsmethoden** erforderlich (keine Sicherheitsfragen!) *(L2)*.

### Prüfung via UI (Entra Admin Center)
1. **Authentifizierungsmethoden:** `Entra Admin Center` → *Protection → Authentication methods → Policies* & *Settings* (hier System-preferred MFA prüfen) & *Registration campaign*.
2. **MFA-Registrierungsbericht:** *Protection → Authentication methods → User registration details* (zeigt pro Benutzer registrierte Methoden, Default-Methode und MFA-Fähigkeit).
3. **Passwortschutz:** *Protection → Authentication methods → Password protection*.
4. **SSPR:** *Identity → Password reset → Properties / Authentication methods*.

### Prüfung via CLI / PowerShell

```powershell
# 1. Authentication Methods Policy (Migration, Methoden, System-preferred MFA)
$authPolicy = Get-MgPolicyAuthenticationMethodPolicy
$authPolicy | Select-Object PolicyMigrationState, RegistrationEnforcement
$authPolicy.AuthenticationMethodConfigurations | Select-Object Id, State

# 2. MFA-Registrierungsstatus aller Benutzer (Bericht!)
$regDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
$regDetails | Group-Object IsMfaCapable | Select-Object Name, Count
# Benutzer OHNE MFA-Fähigkeit auflisten:
$regDetails | Where-Object { -not $_.IsMfaCapable } | Select-Object UserPrincipalName, IsAdmin, MethodsRegistered

# 3. Password Protection / Smart Lockout Settings (via Directory Settings)
Get-MgDirectorySetting | Where-Object { $_.DisplayName -eq "Password Rule Settings" } |
    Select-Object -ExpandProperty Values | Format-Table Name, Value
```

---

## 2.4 Benutzer-, Gruppen-, Portal- & Gast-Einstellungen (External Collaboration)

### Erklärung & Risiko
Standardmäßig erlaubt Microsoft Entra ID regulären Benutzern sehr weitreichende Aktionen: eigene Apps registrieren, das Entra/Azure-Verwaltungsportal öffnen und den gesamten Tenant auslesen, Gäste einladen oder Microsoft-365-Gruppen anlegen.

### Soll-Zustand (CIS 5.1.3.x / 5.1.5.x / 5.1.6.x / L1 & L2)
- **Restrict access to Microsoft Entra admin center:** Aktiviert (`Yes` – verhindert, dass normale Benutzer das Entra-Portal durchsuchen) *(L1)*. *(Hinweis: Blockiert nur das UI, nicht die Graph API – dennoch CIS L1!)*
- **Users can register applications:** Deaktiviert (`No`) *(L1)*.
- **Users can create security groups / M365 groups:** Eingeschränkt (`No` bzw. auf dedizierte Gruppe beschränkt) *(L2)*.
- **LinkedIn account connections:** Deaktiviert (`No`) *(L2)*.
- **External Collaboration Settings:**
  - **Guest user access:** Auf „Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)“ setzen *(L1)*.
  - **Guest invite settings:** Nur Benutzer mit expliziter Rolle (*Guest Inviter* / Admins) dürfen Gäste einladen – nicht „Anyone in the organization“ *(L1)*.
  - **Collaboration restrictions:** Allowlist oder Blocklist für externe Domains (z. B. keine Freemail-Domains) *(L2)*.
- **Cross-Tenant Access Settings:** Default Inbound/Outbound B2B-Einstellungen restriktiv konfiguriert; prüfen, ob MFA-Trust zu fremden Tenants blind aktiviert ist *(L2)*.
- **Verwaiste/inaktive Gastkonten:** Regelmäßige Access Reviews für Gäste *(L2)*.

### Prüfung via UI (Entra Admin Center)
1. **User Settings:** `Entra Admin Center` → *Identity → Users → User settings*.
2. **External Collaboration:** *Identity → External Identities → External collaboration settings*.
3. **Cross-Tenant Access:** *Identity → External Identities → Cross-tenant access settings*.
4. **Group Settings:** *Identity → Groups → Groups settings → General* & *Expiration*.

### Prüfung via CLI / PowerShell

```powershell
# 1. Authorization Policy (App-Registrierung, Admin-Portal, Guest Invite, Guest Role ID!)
# GuestUserRoleId Werte:
#   a0b1b346-4d3e-4e8b-98f8-753987be4970 = Same as member (UNSICHER!)
#   10dae51f-b6af-4016-8d66-8c2a99b929b3 = Limited access (Standard)
#   2af84b1e-32c8-42b7-82bc-daa82404023b = Most restrictive (CIS SOLL!)
$authz = Get-MgPolicyAuthorizationPolicy
[PSCustomObject]@{
    AllowInvitesFrom                       = $authz.AllowInvitesFrom
    GuestUserRoleId                        = $authz.GuestUserRoleId
    AllowedToCreateApps                    = $authz.DefaultUserRolePermissions.AllowedToCreateApps
    AllowedToCreateSecurityGroups          = $authz.DefaultUserRolePermissions.AllowedToCreateSecurityGroups
    AllowedToReadOtherUsers                = $authz.DefaultUserRolePermissions.AllowedToReadOtherUsers
    AllowUserConsentForRiskyApps           = $authz.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
    BlockMsolPowerShell                    = $authz.BlockMsolPowerShell
} | Format-List

# 2. Cross-Tenant Access Default Policy
Get-MgPolicyCrossTenantAccessPolicyDefault | ConvertTo-Json -Depth 6

# 3. Gastbenutzer-Inventar & inaktive Gäste
Get-MgUser -Filter "userType eq 'Guest'" -Property DisplayName,UserPrincipalName,CreatedDateTime,AccountEnabled,SignInActivity -All |
    Select-Object DisplayName, UserPrincipalName, AccountEnabled, CreatedDateTime
```

---

## 2.5 Enterprise Applications, App Registrations & Consent-Governance

### Erklärung & Risiko
**Illicit Consent Grants** (OAuth-Phishing) und **überprivilegierte Service Principals** (z. B. mit `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Directory.ReadWrite.All` oder `Mail.ReadWrite`) gehören zu den gefährlichsten Angriffswegen in Entra ID und M365. Sie umgehen häufig MFA vollständig!

### Soll-Zustand (CIS 5.1.5.x / L1 & L2)
- **User Consent Settings:** „Do not allow user consent“ (CIS L1) oder maximal „Allow user consent for apps from verified publishers, for selected permissions (Low Impact)“.
- **Admin Consent Workflow:** Aktiviert (`Yes`) mit definierten Reviewern *(L1)*.
- **Enterprise Apps – User Assignment Required:** Bei sensiblen Apps aktiviert *(L2)*.
- **High-Privilege App Permissions:** Jede App mit kritischen Application Permissions (`Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Mail.Read`/`Mail.ReadWrite`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`) muss fachlich gerechtfertigt und dokumentiert sein.
- **Secrets & Zertifikate:** Keine abgelaufenen oder extrem langlebigen Client Secrets (> 1–2 Jahre); Zertifikate oder Federated Identity Credentials gegenüber Client Secrets bevorzugen.

### Prüfung via UI (Entra Admin Center)
1. **Consent & Permissions:** `Entra Admin Center` → *Identity → Applications → Enterprise applications → Consent and permissions → User consent settings* & *Admin consent settings*.
2. **Enterprise Apps:** *Enterprise applications → All applications* → Permissions einzelner Apps prüfen (Filter: *Enterprise Applications*).
3. **App Registrations:** *Identity → Applications → App registrations → All applications* → *API permissions* & *Certificates & secrets*.

### Prüfung via CLI / PowerShell

```powershell
# 1. User Consent Policy prüfen
(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
# CIS L1 Soll: leer (= Do not allow user consent)

# 2. Admin Consent Workflow Status prüfen
Get-MgPolicyAdminConsentRequestPolicy | Select-Object IsEnabled, NotifyReviewers, RequestDurationInDays

# 3. Alle Service Principals mit hochkritischen Graph Application Permissions finden
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$appRoleMap = @{}
$graphSp.AppRoles | ForEach-Object { $appRoleMap[$_.Id] = $_.Value }

$criticalPerms = @(
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.Read.All",
    "Files.ReadWrite.All",
    "Sites.FullControl.All"
)

Get-MgServicePrincipal -All | ForEach-Object {
    $sp = $_
    Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All | Where-Object {
        $_.ResourceId -eq $graphSp.Id
    } | ForEach-Object {
        $permName = $appRoleMap[$_.AppRoleId]
        if ($permName -in $criticalPerms) {
            [PSCustomObject]@{
                AppDisplayName = $sp.DisplayName
                AppId          = $sp.AppId
                Permission     = $permName
                Created        = $_.CreatedDateTime
            }
        }
    }
} | Sort-Object Permission | Format-Table -AutoSize

# 4. App Registrations mit Client Secrets (Laufzeit > 365 Tage prüfen!)
Get-MgApplication -All | Where-Object { $_.PasswordCredentials.Count -gt 0 } | ForEach-Object {
    foreach ($cred in $_.PasswordCredentials) {
        [PSCustomObject]@{
            AppName      = $_.DisplayName
            SecretName   = $cred.DisplayName
            StartDate    = $cred.StartDateTime
            EndDate      = $cred.EndDateTime
            DurationDays = ([datetime]$cred.EndDateTime - [datetime]$cred.StartDateTime).Days
        }
    }
} | Format-Table -AutoSize
```

---

## 2.6 Entra Connect (Hybrid), Identity Protection & Diagnostic Logging

### Erklärung & Risiko
In hybriden Umgebungen entscheidet die Anbindung von On-Premises AD an Entra ID über die Widerstandsfähigkeit gegen Credential-Theft (z. B. AD FS Token Forging vs. Password Hash Sync). Zudem speichert Entra ID Sign-in- und Audit-Logs standardmäßig nur **7 Tage (Free) bzw. 30 Tage (P1/P2)** – ohne Export in ein SIEM/Log Analytics fehlen forensische Daten im Ernstfall!

### Soll-Zustand (CIS 5.1.1.x / 5.2.4.x / 5.2.6.x)
- **Hybrid Authentication:** **Password Hash Synchronization (PHS)** aktiviert (auch als Fallback bei PTA/AD FS, um Leaked-Credentials-Erkennung zu ermöglichen).
- **Identity Protection (P2):** Risky Users & Risky Sign-ins werden überwacht und zeitnah bearbeitet (keine dutzenden alten „At risk“-Konten!).
- **Entra Diagnostic Settings:** Export von `AuditLogs`, `SignInLogs`, `NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs`, `ManagedIdentitySignInLogs`, `RiskyUsers`, `UserRiskEvents` an **Log Analytics Workspace** (Microsoft Sentinel) oder Storage Account mit ≥ 90–365 Tagen Aufbewahrung *(Hinweis: Konfiguration der Diagnostic Settings in Entra erfordert Azure-Subscription-Ziel – sichtbar im Entra Portal unter Monitoring → Diagnostic settings)*.

### Prüfung via UI (Entra Admin Center)
1. **Entra Connect / Hybrid:** `Entra Admin Center` → *Identity → Hybrid management → Microsoft Entra Connect → Connect Sync*.
2. **Identity Protection:** *Protection → Identity Protection → Risky users* & *Risky sign-ins* & *Risk detections*.
3. **Diagnostic Settings:** *Identity → Monitoring & health → Diagnostic settings*.

### Prüfung via CLI / PowerShell

```powershell
# 1. Risky Users prüfen (Entra ID P2 + Security Reader / Global Reader)
Get-MgRiskyUser -Filter "riskState eq 'atRisk'" -All |
    Select-Object UserPrincipalName, RiskLevel, RiskState, RiskLastUpdatedDateTime | Format-Table -AutoSize

# 2. Unbestätigte Risk Detections der letzten 30 Tage
Get-MgRiskDetection -Top 50 |
    Select-Object DetectedDateTime, UserPrincipalName, RiskEventType, RiskLevel, RiskState | Format-Table -AutoSize
```

```bash
# 3. Entra ID Diagnostic Settings per Azure CLI prüfen (Achtung: benötigt ggf. Azure RBAC Reader/Security Reader + Entra Global Reader)
az rest --method GET \
  --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" \
  --query "value[].{Name:name, Workspace:properties.workspaceId, Logs:properties.logs[?enabled].category}" -o json
```

---

## 2.7 Typische High-Impact Findings in Kapitel 2

- ❌ Conditional Access Policies stehen dauerhaft auf **Report-only** statt **On**.
- ❌ Breite **Exclusions** (z. B. ganze Gruppen wie „VIPs“, „IT-Admins“ oder „ServiceAccounts“) in der MFA- oder Legacy-Auth-Policy.
- ❌ Mehr als 4 **Global Administrators** oder dauerhaft aktive Admin-Rollen trotz vorhandener Entra ID P2-Lizenzen (PIM nicht genutzt).
- ❌ **On-Premises synchronisierte Konten** mit Global Admin / Security Admin Rechten (AD-Kompromittierung = sofortige Cloud-Kompromittierung).
- ❌ **User Consent** für Drittanbieter-Apps erlaubt oder alte Enterprise Apps mit `Mail.ReadWrite` / `Directory.ReadWrite.All` ohne Owner.
- ❌ **Entra Diagnostic Settings** nicht konfiguriert (Logs gehen nach 30 Tagen verloren).
