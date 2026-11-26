# Kapitel 2: Microsoft Entra ID – Identitäten, Authentifizierung & Zugriffskontrolle

**CIS-Referenz:** CIS Microsoft 365 Foundations Benchmark – *Section 5: Microsoft Entra Admin Center* (L1 & L2) sowie Identity-Grundlagen für Azure  
**Primäres Portal:** **Microsoft Entra Admin Center** (`https://entra.microsoft.com`) *(auch über das Azure Portal unter „Microsoft Entra ID“ erreichbar)*  
**Erforderliche Rollen:** Entra `Global Reader` + Entra `Security Reader` ✅  
**Linux-CLI-Status:** **100 % nativ unter Linux via `az rest` (oder `m365 request`) + `jq` – kein PowerShell erforderlich!**

> [!TIP]
> **Hinweis zu Graph-Scopes:** Falls bei einzelnen Abfragen (`conditionalAccess`, `authenticationMethods`, `riskyUsers`) mit `az rest` ein `403 AccessDenied` erscheint (da Azure CLI nicht für alle Graph-Scopes vorautorisiert ist – siehe [Kapitel 1.5.2](./01-vorbereitung-rollen-und-tools.md#152-anmeldung--wichtige-graph-scope-besonderheit-az-rest-vs-m365)), ersetze `az rest --method GET --url "..."` einfach 1:1 durch `m365 request --url "..." --accept "application/json" --output json`!

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
2. **Conditional Access:** `Entra Admin Center` → *Protection → Conditional Access → Policies* → Status (`On` vs. `Report-only`), *Users → Exclude*, *Conditions (Client apps)* und *Grant / Session Controls* prüfen.
3. **Named Locations:** *Protection → Conditional Access → Named locations* → prüfen, ob „Trusted IPs“ MFA umgehen.

### Prüfung via Linux CLI (`az rest` / `m365` + `jq`)

```bash
# 1. Security Defaults Status prüfen
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" \
  --query "{IsEnabled:isEnabled, DisplayName:displayName}" -o table

# 2. Alle Conditional Access Policies inkl. Status, Exclusions & Grant Controls ausgeben
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -o json \
| jq -r '
  ["Name","State","ClientApps","GrantControls","AuthStrength","ExcludeUsers","ExcludeGroups","ExcludeRoles"],
  (.value[] | [
    .displayName,
    .state,
    ((.conditions.clientAppTypes // []) | join(",")),
    ((.grantControls.builtInControls // []) | join(",")),
    (.grantControls.authenticationStrength.displayName // "-"),
    ((.conditions.users.excludeUsers // []) | length | tostring),
    ((.conditions.users.excludeGroups // []) | length | tostring),
    ((.conditions.users.excludeRoles // []) | length | tostring)
  ]) | @tsv' | column -t -s $'\t'

# 3. Vollständigen JSON-Export als Evidenz speichern
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  -o json > evidence/02-entra/ca-policies.json

# 4. Named Locations (insb. isTrusted == true prüfen!)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" \
  --query "value[].{Name:displayName, Type:\"@odata.type\", Trusted:isTrusted}" -o table
```

---

## 2.2 Privilegierte Rollen, Global Admins, Break-Glass-Konten & PIM

### Erklärung & Risiko
Übermäßige, dauerhaft zugewiesene oder aus dem On-Premises-AD synchronisierte Admin-Konten sind der Hauptvektor für vollständige Tenant-Kompromittierungen (inkl. Hybrid-Lateral-Movement von On-Prem nach Cloud).

### Soll-Zustand (CIS 5.1.x / 5.3.x / L1 & L2)
- **Anzahl Global Administrators:** Mindestens **2**, höchstens **4** (inkl. Break-Glass-Konten) *(L1)*.
- **Dedizierte Cloud-only Admin-Konten:** Keine produktive E-Mail/M365-Lizenz, **keine** Synchronisation aus On-Premises AD (`onPremisesSyncEnabled != true`) *(L1)*.
- **Notfallkonten (Break-Glass):** 2 dedizierte Cloud-only-Konten (`*.onmicrosoft.com`), Phishing-resistente Authentifizierung (FIDO2-Hardware-Keys), ausgeschlossen von fehleranfälligen CA-Policies, mit **Login-Alerting** überwacht *(L1)*.
- **Privileged Identity Management (PIM – erfordert Entra ID P2):**
  - Privilegierte Rollen sind **Eligible**, nicht dauerhaft **Active** *(L2)*.
  - Aktivierung erfordert **MFA**, **Begründung**, zeitliche Begrenzung (z. B. ≤ 8 Std.) und für kritische Rollen **Genehmigung (Approval)** *(L2)*.
  - Regelmäßige **Access Reviews** für privilegierte Rollen eingerichtet *(L2)*.

### Prüfung via UI (Entra Admin Center)
1. **Aktive Rollenzuweisungen:** `Entra Admin Center` → *Identity → Roles & admins → Roles & admins* → *Global Administrator* (und weitere hochprivilegierte Rollen) → Reiter *Assignments*.
2. **PIM (falls P2 lizenziert):** `Entra Admin Center` → *Identity Governance → Privileged Identity Management → Microsoft Entra roles* → *Assignments* (Eligible vs. Active), *Settings* und *Access reviews*.

### Prüfung via Linux CLI (`az rest` + `jq`)

```bash
# 1. Global Administrators (inkl. On-Prem-Sync-Status & AccountEnabled)
GA_ID=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoles" \
  --query "value[?displayName=='Global Administrator'].id | [0]" -o tsv)

az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/directoryRoles/${GA_ID}/members?\$select=displayName,userPrincipalName,onPremisesSyncEnabled,accountEnabled" \
  --query "value[].{Name:displayName, UPN:userPrincipalName, Synced:onPremisesSyncEnabled, Enabled:accountEnabled}" -o table

# 2. ALLE aktiven (dauerhaften) Entra-Rollenzuweisungen im Tenant auflisten
az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoles" -o json \
| jq -r '.value[] | "\(.id)\t\(.displayName)"' \
| while IFS=$'\t' read -r rid rname; do
    az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoles/${rid}/members" -o json \
    | jq -r --arg role "$rname" '.value[] | [$role, .displayName, (.userPrincipalName // .appId // "-"), (.onPremisesSyncEnabled // false | tostring)] | @tsv'
  done | column -t -s $'\t'

# 3. PIM Eligible vs. Active Schedule Instances (erfordert Entra ID P2)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?\$expand=roleDefinition,principal" \
  --query "value[].{Role:roleDefinition.displayName, Principal:principal.displayName, UPN:principal.userPrincipalName, End:endDateTime}" -o table

az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?\$expand=roleDefinition,principal" \
  --query "value[].{Role:roleDefinition.displayName, Principal:principal.displayName, Type:assignmentType, End:endDateTime}" -o table
```

---

## 2.3 Authentifizierungsmethoden, MFA-Härtung & Passwortschutz

### Erklärung & Risiko
Schwache MFA-Methoden wie **SMS** oder **Voice Call** sind anfällig für SIM-Swapping und Social Engineering. Fehlende Number-Matching-/Kontext-Informationen ermöglichen **MFA-Fatigue-Angriffe**. Schwache Passwörter ohne Smart Lockout begünstigen Password Spraying.

### Soll-Zustand (CIS 5.2.3.x / L1 & L2)
- **Authentication Methods Policy Migration:** Abgeschlossen (`migrationComplete`) *(L1)*.
- **Microsoft Authenticator:** Number Matching, App-Kontext & Standortanzeige aktiv *(L1)*.
- **FIDO2 / Passkeys** aktiviert (mind. für Admins) *(L2)*.
- **SMS & Voice Call** deaktiviert oder strikt auf Ausnahmegruppen beschränkt *(L1/L2)*.
- **System-preferred MFA** aktiviert *(L1)*.
- **MFA-Registrierungsstatus:** 100 % der Admins und idealerweise 100 % aller aktiven Benutzer sind MFA-fähig *(L1)*.
- **Entra Password Protection:** Smart Lockout konfiguriert (z. B. Threshold ≤ 10, Lockout Duration ≥ 60 Sek.), Custom Banned Password List aktiv, bei Hybrid-AD auch **On-Premises Proxy/DC Agent** aktiv *(L1/L2)*.
- **SSPR:** Wenn aktiviert, mindestens **2 Authentifizierungsmethoden** (keine Sicherheitsfragen!) *(L2)*.

### Prüfung via UI (Entra Admin Center)
1. **Authentifizierungsmethoden:** `Entra Admin Center` → *Protection → Authentication methods → Policies*, *Settings* (System-preferred MFA) & *Registration campaign*.
2. **MFA-Registrierungsbericht:** *Protection → Authentication methods → User registration details*.
3. **Passwortschutz:** *Protection → Authentication methods → Password protection*.
4. **SSPR:** *Identity → Password reset → Properties / Authentication methods*.

### Prüfung via Linux CLI (`az rest` / `m365` + `jq`)

```bash
# 1. Authentication Methods Policy (Migration, Methoden, System-preferred MFA)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy" -o json \
| jq '{
    migrationState: .policyMigrationState,
    systemCredentialPreferences: .systemCredentialPreferences,
    methods: [.authenticationMethodConfigurations[] | {id: .id, state: .state}]
  }'

# 2. MFA-Registrierungsbericht: Benutzer OHNE MFA-Fähigkeit auflisten
# (Bei 403 mit az rest -> 'm365 request --url ... --output json' nutzen!)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?\$top=999" -o json \
| jq -r '
  "=== Zusammenfassung ===",
  "Gesamt: \(.value | length) | MFA-fähig: \([.value[] | select(.isMfaCapable == true)] | length) | OHNE MFA: \([.value[] | select(.isMfaCapable == false)] | length)",
  "",
  "=== Admins OHNE MFA ===",
  (.value[] | select(.isAdmin == true and .isMfaCapable == false) | "\(.userPrincipalName)\tAdmin=\(.isAdmin)\tMethoden=\(.methodsRegistered | join(","))")
'

# 3. Password Protection / Smart Lockout Settings (Directory Settings)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/groupSettings" -o json \
| jq '.value[] | select(.displayName == "Password Rule Settings") | .values'
```

---

## 2.4 Benutzer-, Gruppen-, Portal- & Gast-Einstellungen (External Collaboration)

### Erklärung & Risiko
Standardmäßig erlaubt Microsoft Entra ID regulären Benutzern sehr weitreichende Aktionen: eigene Apps registrieren, das Entra/Azure-Verwaltungsportal öffnen und den gesamten Tenant auslesen, Gäste einladen oder M365-Gruppen anlegen.

### Soll-Zustand (CIS 5.1.3.x / 5.1.5.x / 5.1.6.x / L1 & L2)
- **Restrict access to Microsoft Entra admin center:** Aktiviert (`Yes`) *(L1)*.
- **Users can register applications:** Deaktiviert (`No`) *(L1)*.
- **Users can create security groups / M365 groups:** Eingeschränkt *(L2)*.
- **LinkedIn account connections:** Deaktiviert *(L2)*.
- **External Collaboration Settings:**
  - **Guest user access:** „Most restrictive“ (`guestUserRoleId == 2af84b1e-32c8-42b7-82bc-daa82404023b`) *(L1)*.
  - **Guest invite settings:** Nur Admins / Guest Inviter (`adminsAndGuestInviters` oder `none`) *(L1)*.
  - **Collaboration restrictions:** Allowlist/Blocklist für externe Domains *(L2)*.
- **Cross-Tenant Access Settings:** Default Inbound/Outbound B2B restriktiv; prüfen, ob fremdes MFA blind vertraut wird *(L2)*.

### Prüfung via UI (Entra Admin Center)
1. **User Settings:** `Entra Admin Center` → *Identity → Users → User settings*.
2. **External Collaboration:** *Identity → External Identities → External collaboration settings*.
3. **Cross-Tenant Access:** *Identity → External Identities → Cross-tenant access settings*.
4. **Group Settings:** *Identity → Groups → Groups settings → General* & *Expiration*.

### Prüfung via Linux CLI (`az rest` + `jq`)

```bash
# 1. Authorization Policy (App-Erstellung, Guest Role, Guest Invite, User Consent!)
# GuestUserRoleId:
#   a0b1b346-4d3e-4e8b-98f8-753987be4970 = Same as member (UNSICHER!)
#   10dae51f-b6af-4016-8d66-8c2a99b929b3 = Limited access (Standard)
#   2af84b1e-32c8-42b7-82bc-daa82404023b = Most restrictive (CIS SOLL!)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -o json \
| jq '{
    allowInvitesFrom: .allowInvitesFrom,
    guestUserRoleId: .guestUserRoleId,
    allowedToCreateApps: .defaultUserRolePermissions.allowedToCreateApps,
    allowedToCreateSecurityGroups: .defaultUserRolePermissions.allowedToCreateSecurityGroups,
    allowedToReadOtherUsers: .defaultUserRolePermissions.allowedToReadOtherUsers,
    permissionGrantPoliciesAssigned: .defaultUserRolePermissions.permissionGrantPoliciesAssigned,
    blockMsolPowerShell: .blockMsolPowerShell
  }'

# 2. Cross-Tenant Access Default Policy
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default" -o json | jq .

# 3. Gastbenutzer-Inventar
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/users?\$filter=userType eq 'Guest'&\$select=displayName,userPrincipalName,accountEnabled,createdDateTime&\$top=999" \
  --query "value[].{Name:displayName, UPN:userPrincipalName, Enabled:accountEnabled, Created:createdDateTime}" -o table
```

---

## 2.5 Enterprise Applications, App Registrations & Consent-Governance

### Erklärung & Risiko
**Illicit Consent Grants** (OAuth-Phishing) und **überprivilegierte Service Principals** (z. B. mit `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Directory.ReadWrite.All` oder `Mail.ReadWrite`) umgehen häufig MFA vollständig und zählen zu den gefährlichsten Angriffswegen in Entra ID und M365.

### Soll-Zustand (CIS 5.1.5.x / L1 & L2)
- **User Consent Settings:** „Do not allow user consent“ (`permissionGrantPoliciesAssigned` leer) *(L1)*.
- **Admin Consent Workflow:** Aktiviert (`isEnabled: true`) mit definierten Reviewern *(L1)*.
- **Enterprise Apps – User Assignment Required:** Bei sensiblen Apps aktiviert *(L2)*.
- **High-Privilege App Permissions:** Jede App mit kritischen Application Permissions muss fachlich gerechtfertigt sein.
- **Secrets & Zertifikate:** Keine abgelaufenen oder langlebigen Client Secrets (> 365 Tage); Zertifikate oder Federated Identity Credentials bevorzugen.

### Prüfung via UI (Entra Admin Center)
1. **Consent & Permissions:** `Entra Admin Center` → *Identity → Applications → Enterprise applications → Consent and permissions → User consent settings* & *Admin consent settings*.
2. **Enterprise Apps:** *Enterprise applications → All applications* → Permissions einzelner Apps prüfen.
3. **App Registrations:** *Identity → Applications → App registrations → All applications* → *API permissions* & *Certificates & secrets*.

### Prüfung via Linux CLI (`az rest` + `jq`)

```bash
# 1. User Consent Policy prüfen (CIS L1 Soll: [])
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" \
  --query "defaultUserRolePermissions.permissionGrantPoliciesAssigned" -o json

# 2. Admin Consent Workflow Status prüfen
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy" \
  --query "{IsEnabled:isEnabled, NotifyReviewers:notifyReviewers, DurationDays:requestDurationInDays}" -o table

# 3. Alle Apps mit hochkritischen Microsoft Graph Application Permissions finden!
GRAPH_SP_ID=$(az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId eq '00000003-0000-0000-c000-000000000000'&\$select=id" \
  --query "value[0].id" -o tsv)

# AppRole-ID -> Name Mapping laden und gegen alle Zuweisungen auf Microsoft Graph abgleichen
GRAPH_ROLES=$(az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/${GRAPH_SP_ID}?\$select=appRoles" -o json)

az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/${GRAPH_SP_ID}/appRoleAssignedTo?\$top=999" -o json \
| jq -r --argjson roles "$GRAPH_ROLES" '
  ($roles.appRoles | map({(.id): .value}) | add) as $map |
  ["PrincipalName","Permission","Created"],
  (.value[] | ($map[.appRoleId] // .appRoleId) as $perm |
    select($perm | IN(
      "RoleManagement.ReadWrite.Directory","AppRoleAssignment.ReadWrite.All",
      "Application.ReadWrite.All","Directory.ReadWrite.All","User.ReadWrite.All",
      "Group.ReadWrite.All","Mail.Read","Mail.ReadWrite","Mail.Send",
      "Files.Read.All","Files.ReadWrite.All","Sites.FullControl.All"
    )) |
    [.principalDisplayName, $perm, .createdDateTime]
  ) | @tsv' | column -t -s $'\t'

# 4. App Registrations mit Client Secrets & deren Laufzeit prüfen
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/applications?\$select=displayName,appId,passwordCredentials&\$top=999" -o json \
| jq -r '
  ["AppName","SecretName","StartDate","EndDate"],
  (.value[] | select((.passwordCredentials | length) > 0) | .displayName as $app |
    .passwordCredentials[] | [$app, (.displayName // "-"), .startDateTime, .endDateTime]
  ) | @tsv' | column -t -s $'\t'
```

---

## 2.6 Entra Connect (Hybrid), Identity Protection & Diagnostic Logging

### Erklärung & Risiko
In hybriden Umgebungen entscheidet die AD-Anbindung über die Widerstandsfähigkeit gegen Credential-Theft (Password Hash Sync vs. AD FS). Zudem speichert Entra ID Sign-in- und Audit-Logs standardmäßig nur **7 Tage (Free) bzw. 30 Tage (P1/P2)** – ohne Export in ein SIEM/Log Analytics fehlen forensische Daten im Ernstfall!

### Soll-Zustand (CIS 5.1.1.x / 5.2.4.x / 5.2.6.x)
- **Hybrid Authentication:** **Password Hash Synchronization (PHS)** aktiv (auch als Fallback für Leaked-Credentials-Erkennung).
- **Identity Protection (P2):** Risky Users & Risky Sign-ins werden zeitnah bearbeitet (keine alten „At risk“-Konten!).
- **Entra Diagnostic Settings:** Export von `AuditLogs`, `SignInLogs`, `NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs`, `ManagedIdentitySignInLogs`, `RiskyUsers`, `UserRiskEvents` an **Log Analytics Workspace** (Microsoft Sentinel) oder Storage Account.

### Prüfung via UI (Entra Admin Center)
1. **Entra Connect / Hybrid:** `Entra Admin Center` → *Identity → Hybrid management → Microsoft Entra Connect → Connect Sync*.
2. **Identity Protection:** *Protection → Identity Protection → Risky users* & *Risky sign-ins* & *Risk detections*.
3. **Diagnostic Settings:** *Identity → Monitoring & health → Diagnostic settings*.

### Prüfung via Linux CLI (`az rest` / `m365` + `jq`)

```bash
# 1. Risky Users prüfen (Entra ID P2 + Security Reader / Global Reader)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?\$filter=riskState eq 'atRisk'" \
  --query "value[].{UPN:userPrincipalName, Level:riskLevel, State:riskState, Updated:riskLastUpdatedDateTime}" -o table

# 2. Letzte Risk Detections prüfen
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?\$top=50" \
  --query "value[].{Detected:detectedDateTime, UPN:userPrincipalName, Type:riskEventType, Level:riskLevel, State:riskState}" -o table

# 3. Entra ID Diagnostic Settings prüfen (ARM API)
az rest --method GET \
  --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" \
  --query "value[].{Name:name, Workspace:properties.workspaceId, Logs:properties.logs[?enabled].category}" -o json
```

---

## 2.7 Typische High-Impact Findings in Kapitel 2

- ❌ Conditional Access Policies stehen dauerhaft auf **Report-only** statt **On**.
- ❌ Breite **Exclusions** (z. B. Gruppen wie „VIPs“, „IT-Admins“, „ServiceAccounts“) in MFA- oder Legacy-Auth-Policies.
- ❌ Mehr als 4 **Global Administrators** oder dauerhaft aktive Admin-Rollen trotz Entra ID P2 (PIM nicht genutzt).
- ❌ **On-Premises synchronisierte Konten** mit Global Admin / Security Admin Rechten.
- ❌ **User Consent** erlaubt oder alte Enterprise Apps mit `Mail.ReadWrite` / `Directory.ReadWrite.All` ohne Owner.
- ❌ **Entra Diagnostic Settings** nicht konfiguriert (Logs gehen nach 30 Tagen verloren).
