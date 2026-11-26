# Kapitel 3: Microsoft 365 Admin Center – Tenant-Grundlagen & Governance

**CIS-Referenz:** CIS Microsoft 365 Foundations Benchmark – *Section 1: Microsoft 365 Admin Center* (L1 & L2)  
**Primäres Portal:** **Microsoft 365 Admin Center** (`https://admin.microsoft.com`)  
**Erforderliche Rollen:** Entra `Global Reader` ✅ *(Der Bereich „Billing / Purchase Services“ ist für Global Reader eingeschränkt; alle sicherheitsrelevanten Org Settings sind einsehbar.)*  
**Linux-CLI-Status:** **Überwiegend 100 % nativ unter Linux via `az rest` (oder `m365 request`) + `jq`!** Nur 3 Exchange-spezifische Eigenschaften (*Shared-Mailbox-Typ*, *Customer Lockbox*, *Sharing Policy*) besitzen keine Graph-API und werden unter Linux per `pwsh` (`ExchangeOnlineManagement`) oder über die UI geprüft.

---

## 3.1 Administrative Konten & Lizenz-Trennung

### Erklärung & Risiko
Wenn Administratoren mit demselben Konto produktiv E-Mails lesen, im Web surfen und gleichzeitig Tenant-Administration betreiben, führt bereits ein einziger Phishing-Klick zur Übernahme des gesamten Tenants.

### Soll-Zustand (CIS 1.1.1 – 1.1.3 / L1)
- Administrative Konten sind **dediziert** (getrennt vom produktiven Benutzerkonto), **Cloud-only** und besitzen **keine produktiven M365-E-Mail-Lizenzen** (Exchange Online / Office-Suite) *(L1)*.
- Zwischen **2 und 4 Global Administrators** (vgl. Kapitel 2.2) *(L1)*.
- **Alternative E-Mail-Adresse** für Benachrichtigungen im M365 Admin Center hinterlegt *(L1)*.

### Prüfung via UI (M365 Admin Center)
- `M365 Admin Center` → *Users → Active users* → Filter nach Admin-Rollen (*View → Global admins* / *Exchange admins*). Prüfen, ob produktive Lizenzen (`Microsoft 365 E3/E5`, `Exchange Online`) zugewiesen sind.
- `M365 Admin Center` → *Roles → Role assignments* → Überblick über alle M365-Rollen.

### Prüfung via Linux CLI (`az rest` + `jq`)

```bash
# Prüfen, welche Global Admins eine produktive M365-Lizenz tragen oder On-Prem gesynct sind
GA_ID=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoles" \
  --query "value[?displayName=='Global Administrator'].id | [0]" -o tsv)

az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/directoryRoles/${GA_ID}/members?\$select=displayName,userPrincipalName,assignedLicenses,onPremisesSyncEnabled,accountEnabled" \
  -o json \
| jq -r '
  ["DisplayName","UPN","LicenseCount","OnPremSynced","Enabled"],
  (.value[] | [
    .displayName,
    (.userPrincipalName // "-"),
    ((.assignedLicenses // []) | length | tostring),
    ((.onPremisesSyncEnabled // false) | tostring),
    ((.accountEnabled // false) | tostring)
  ]) | @tsv' | column -t -s $'\t'
```

---

## 3.2 Shared Mailboxes – Anmeldung blockieren

### Erklärung & Risiko
Shared Mailboxes (freigegebene Postfächer, z. B. `info@`, `buchhaltung@`) sind nicht personenbezogen und werden häufig ohne MFA betrieben. Bleibt der direkte Sign-In für das zugehörige Entra-Benutzerkonto aktiviert, können Angreifer sich direkt mit Passwort (oder gestohlenem Token) anmelden.

### Soll-Zustand (CIS 1.2.x / L1)
- Für **alle** Shared Mailboxes ist das zugrunde liegende Benutzerkonto im Status **Sign-in blocked** (`accountEnabled = false`). Der Zugriff erfolgt ausschließlich über delegierte Postfachberechtigungen (*Full Access / Send As*) normaler MFA-geschützter Benutzerkonten.

### Prüfung via UI (M365 Admin Center)
- `M365 Admin Center` → *Teams & groups → Shared mailboxes* → Postfächer notieren und in *Users → Active users* prüfen, ob der Status auf **Sign-in blocked** steht.

### Prüfung via Linux CLI

```bash
# 1. Schneller Indikator rein per Linux CLI (az rest):
#    Aktive (accountEnabled==true) Benutzerkonten MIT E-Mail-Adresse, aber OHNE zugewiesene Lizenz
#    (Shared Mailboxes haben i. d. R. keine eigene Lizenz!)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/users?\$filter=accountEnabled eq true&\$select=displayName,userPrincipalName,mail,assignedLicenses,userType&\$top=999" \
  -o json \
| jq -r '
  ["DisplayName","UPN","Mail","Licenses"],
  (.value[] | select(.userType == "Member" and (.mail != null) and ((.assignedLicenses | length) == 0)) |
    [.displayName, .userPrincipalName, .mail, "0 (Pruefen ob Shared Mailbox!)"]
  ) | @tsv' | column -t -s $'\t'
```

```bash
# 2. Exakter Abgleich über Exchange Online (nur via Linux pwsh möglich, da Graph keinen RecipientTypeDetails hat):
pwsh -NoLogo -Command '
  Connect-ExchangeOnline -Device -UserPrincipalName "auditor@kunde.de" -ShowBanner:$false
  Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited |
    Select-Object DisplayName, PrimarySmtpAddress, ExternalDirectoryObjectId |
    ConvertTo-Json
  Disconnect-ExchangeOnline -Confirm:$false
' | jq -r '.[] | .ExternalDirectoryObjectId' | while read -r oid; do
  az rest --method GET \
    --url "https://graph.microsoft.com/v1.0/users/${oid}?\$select=displayName,userPrincipalName,accountEnabled" \
    --query "[?accountEnabled==\`true\`].{Name:displayName, UPN:userPrincipalName, Enabled:accountEnabled}" -o tsv 2>/dev/null
done
```

---

## 3.3 Öffentliche Microsoft 365 Gruppen (Public Groups)

### Erklärung & Risiko
Jede **öffentliche (Public)** Microsoft-365-Gruppe ermöglicht es **jedem Benutzer im gesamten Tenant** (und je nach Einstellung sogar Gästen), ohne Genehmigung beizutreten und sämtliche SharePoint-Dokumente, Teams-Chats und E-Mails der Gruppe einzusehen.

### Soll-Zustand (CIS 1.2.x / L2)
- Keine sensiblen oder unbeabsichtigt als `Public` erstellten M365-Gruppen; Standard für neue Gruppen sollte `Private` sein.

### Prüfung via UI (M365 Admin Center)
- `M365 Admin Center` → *Teams & groups → Active teams & groups* → Spalte **Privacy** nach `Public` filtern.

### Prüfung via Linux CLI (`az rest` + `jq`)

```bash
# Alle öffentlichen Microsoft 365 Gruppen (Unified + Visibility=Public) auflisten
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/groups?\$filter=groupTypes/any(c:c eq 'Unified') and visibility eq 'Public'&\$select=displayName,mail,visibility,createdDateTime&\$top=999" \
  --query "value[].{Name:displayName, Mail:mail, Visibility:visibility, Created:createdDateTime}" -o table
```

---

## 3.4 Passwort-Ablaufpolitik (Password Expiration Policy)

### Erklärung & Risiko
Nach aktueller NIST SP 800-63B- und CIS-Empfehlung führt ein erzwungener periodischer Passwortwechsel (z. B. alle 90 Tage) zu vorhersagbaren, schwächeren Passwörtern und bietet keinen Sicherheitsgewinn gegenüber MFA + Password Protection + Risk-based CA.

### Soll-Zustand (CIS 1.3.x / L1)
- **Set passwords to never expire** aktiviert (`passwordValidityPeriodInDays == 2147483647`), vorausgesetzt MFA, Entra Password Protection & Identity Protection sind aktiv.

### Prüfung via UI (M365 Admin Center)
- `M365 Admin Center` → *Settings → Org settings → Security & privacy → Password expiration policy*.

### Prüfung via Linux CLI (`az rest`)

```bash
# PasswordValidityPeriodInDays für alle Domains prüfen (2147483647 = Never expire)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/domains" \
  --query "value[].{Domain:id, ValidDays:passwordValidityPeriodInDays, NotifyDays:passwordNotificationWindowInDays}" -o table
```

---

## 3.5 Idle Session Timeout, Kalenderfreigabe, User-Owned Apps & Customer Lockbox

### Erklärung & Risiko
- **Idle Session Timeout:** Verhindert unbefugte Weiternutzung offener M365-Web-Sessions an gemeinsam genutzten oder unbeaufsichtigten Geräten.
- **Externe Kalenderfreigabe:** Wenn Kalenderdetails (Betreff, Teilnehmer, Ort) standardmäßig anonym oder extern geteilt werden können, fließen vertrauliche Geschäftsinformationen ab.
- **User-Owned Apps / Integrated Apps / Office Store:** Ungesteuerte Drittanbieter-Add-ins erweitern die Angriffsfläche für Datenabfluss.
- **Customer Lockbox:** Erzwingt explizite Kundenfreigabe, bevor Microsoft-Support-Ingenieure im Supportfall Zugriff auf Kundendaten erhalten.

### Soll-Zustand (CIS 1.3.x / L1 & L2)
- **Idle session timeout:** Aktiviert (CIS-Empfehlung: ≤ **3 Stunden**, idealerweise 1 Stunde auf unmanaged Devices) *(L1)*.
- **Calendar sharing:** Externe anonyme Freigabe deaktiviert oder auf *Free/Busy only* begrenzt *(L2)*.
- **User-owned apps and services:** „Let users access the Microsoft 365 Store“ & „Let users start trials on behalf of your org“ deaktiviert *(L1/L2)*.
- **Integrated apps / User consent:** Eingeschränkt (siehe Kapitel 2.5) *(L1)*.
- **Customer Lockbox:** Aktiviert (falls E5 / Compliance-Lizenz vorhanden) *(L2)*.
- **Modern Authentication (M365 Admin):** Aktiviert für alle Protokolle *(L1)*.

### Prüfung via UI (M365 Admin Center)
Alle Punkte befinden sich unter **`M365 Admin Center` → *Settings → Org settings***:
1. **Security & privacy:** *Idle session timeout*, *Password expiration policy*, *Customer Lockbox*, *Privacy profile*.
2. **Services:** *Calendar*, *Modern authentication*, *User owned apps and services*, *Microsoft Forms*, *Sway*, *Microsoft 365 Groups*, *Microsoft 365 on the web*.
3. **Integrated apps:** `M365 Admin Center` → *Settings → Integrated apps*.

### Prüfung via Linux CLI

```bash
# 1. Idle Session Timeout (nativ Linux CLI via Microsoft Graph REST!)
#    (Bei 403 mit az rest -> 'm365 request --url ... --output json' nutzen)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/policies/activityBasedTimeoutPolicies" -o json | jq .

# 2. M365 Groups Guest Settings (nativ Linux CLI via Microsoft Graph REST!)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/groupSettings" -o json \
| jq '.value[] | select(.displayName == "Group.Unified") | .values'

# 3. Customer Lockbox, Modern Auth & Externe Kalenderfreigabe (Sharing Policy)
#    [Microsoft-Limit: nur in Exchange Online verfügbar -> Aufruf direkt aus Linux-Bash über pwsh:]
pwsh -NoLogo -Command '
  Connect-ExchangeOnline -Device -UserPrincipalName "auditor@kunde.de" -ShowBanner:$false
  Get-OrganizationConfig | Select-Object CustomerLockboxEnabled, OAuth2ClientProfileEnabled | Format-List
  Get-SharingPolicy | Select-Object Name, Enabled, Domains | Format-Table -AutoSize
  Disconnect-ExchangeOnline -Confirm:$false
'
```

> [!NOTE]
> Einige Einstellungen im M365 Admin Center (*Idle session timeout* UI-Toggle, *User-owned apps & services*, *Forms*, *Sway*) sind in den CIS Benchmarks als **Manual** klassifiziert und sollten zusätzlich direkt über die **UI** (`admin.microsoft.com → Settings → Org settings`) verifiziert und per Screenshot dokumentiert werden.
