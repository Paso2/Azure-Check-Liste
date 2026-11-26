# Kapitel 3: Microsoft 365 Admin Center – Tenant-Grundlagen & Governance

**CIS-Referenz:** CIS Microsoft 365 Foundations Benchmark – *Section 1: Microsoft 365 Admin Center* (L1 & L2)  
**Primäres Portal:** **Microsoft 365 Admin Center** (`https://admin.microsoft.com`)  
**Erforderliche Rollen:** Entra `Global Reader` ✅ *(Hinweis: Der Bereich „Billing / Purchase Services“ ist für Global Reader eingeschränkt; alle sicherheitsrelevanten Org Settings sind einsehbar.)*

---

## 3.1 Administrative Konten & Lizenz-Trennung

### Erklärung & Risiko
Wenn Administratoren mit demselben Konto produktiv E-Mails lesen, im Web surfen und gleichzeitig Tenant-Administration betreiben, führt bereits ein einziger Phishing-Klick zur Übernahme des gesamten Tenants.

### Soll-Zustand (CIS 1.1.1 – 1.1.3 / L1)
- Administrative Konten sind **dediziert** (getrennt vom produktiven Benutzerkonto), **Cloud-only** und besitzen **keine produktiven M365-E-Mail-Lizenzen** (Exchange Online / Office-Suite) *(L1)*.
- Zwischen **2 und 4 Global Administrators** (vgl. Kapitel 2.2) *(L1)*.
- **Alternative E-Mail-Adresse** für Benachrichtigungen im M365 Admin Center hinterlegt *(L1)*.

### Prüfung via UI (M365 Admin Center)
- `M365 Admin Center` → *Users → Active users* → Filter nach Admin-Rollen (*View → Global admins* / *Billing admins* / *Exchange admins*). Prüfen, ob Lizenzen wie `Microsoft 365 E3/E5` oder `Exchange Online` zugewiesen sind.
- `M365 Admin Center` → *Roles → Role assignments* → Überblick über alle M365-Rollen.

### Prüfung via CLI / PowerShell

```powershell
# Prüfen, welche Global Admins / Privileged Admins eine produktive M365/Exchange-Lizenz tragen
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id | ForEach-Object {
    $user = Get-MgUser -UserId $_.Id -Property DisplayName,UserPrincipalName,AssignedLicenses,OnPremisesSyncEnabled
    [PSCustomObject]@{
        DisplayName  = $user.DisplayName
        UPN          = $user.UserPrincipalName
        LicenseCount = $user.AssignedLicenses.Count
        OnPremSynced = $user.OnPremisesSyncEnabled
    }
} | Format-Table -AutoSize
```

---

## 3.2 Shared Mailboxes – Anmeldung blockieren

### Erklärung & Risiko
Shared Mailboxes (freigegebene Postfächer, z. B. `info@`, `buchhaltung@`) sind nicht personenbezogen und werden häufig ohne MFA betrieben. Bleibt der direkte Sign-In für das zugehörige Entra-Benutzerkonto aktiviert, können Angreifer sich direkt mit Passwort (oder gestohlenem Token) anmelden.

### Soll-Zustand (CIS 1.2.x / L1)
- Für **alle** Shared Mailboxes ist das zugrunde liegende Benutzerkonto im Status **Sign-in blocked** (`AccountEnabled = $false`). Der Zugriff erfolgt ausschließlich über delegierte Postfachberechtigungen (*Full Access / Send As*) normaler MFA-geschützter Benutzerkonten.

### Prüfung via UI (M365 Admin Center)
- `M365 Admin Center` → *Teams & groups → Shared mailboxes* → einzelne Postfächer anklicken oder in *Users → Active users* nach den Shared-Mailbox-Konten filtern und Status **Sign-in blocked** prüfen.

### Prüfung via CLI / PowerShell

```powershell
# Alle Shared Mailboxes aus Exchange Online abrufen und gegen Entra ID AccountEnabled prüfen
$sharedMailboxes = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited
$findings = foreach ($mbx in $sharedMailboxes) {
    $entraUser = Get-MgUser -UserId $mbx.ExternalDirectoryObjectId -Property AccountEnabled,UserPrincipalName -ErrorAction SilentlyContinue
    if ($entraUser.AccountEnabled -eq $true) {
        [PSCustomObject]@{
            DisplayName    = $mbx.DisplayName
            PrimarySmtp    = $mbx.PrimarySmtpAddress
            UPN            = $entraUser.UserPrincipalName
            AccountEnabled = $entraUser.AccountEnabled
        }
    }
}
$findings | Format-Table -AutoSize
```

---

## 3.3 Öffentliche Microsoft 365 Gruppen (Public Groups)

### Erklärung & Risiko
Jede **öffentliche (Public)** Microsoft-365-Gruppe ermöglicht es **jedem Benutzer im gesamten Tenant** (und je nach Einstellung sogar Gästen), ohne Genehmigung beizutreten und sämtliche SharePoint-Dokumente, Teams-Chats und E-Mails der Gruppe einzusehen.

### Soll-Zustand (CIS 1.2.x / L2)
- Keine sensiblen oder unbeabsichtigt als `Public` erstellten M365-Gruppen; Standard für neue Gruppen sollte `Private` sein.

### Prüfung via UI (M365 Admin Center)
- `M365 Admin Center` → *Teams & groups → Active teams & groups* → Spalte **Privacy** nach `Public` filtern.

### Prüfung via CLI / PowerShell

```powershell
# Alle öffentlichen Microsoft 365 Gruppen auflisten
Get-MgGroup -Filter "groupTypes/any(c:c eq 'Unified') and visibility eq 'Public'" -All |
    Select-Object DisplayName, Mail, Visibility, CreatedDateTime | Format-Table -AutoSize
```

---

## 3.4 Passwort-Ablaufpolitik (Password Expiration Policy)

### Erklärung & Risiko
Nach aktueller NIST SP 800-63B- und CIS-Empfehlung führt ein erzwungener periodischer Passwortwechsel (z. B. alle 90 Tage) zu vorhersagbaren, schwächeren Passwörtern (`Sommer2026!` → `Herbst2026!`) und bietet keinen Sicherheitsgewinn gegenüber MFA + Password Protection + Risk-based CA.

### Soll-Zustand (CIS 1.3.x / L1)
- **Set passwords to never expire** aktiviert (vorausgesetzt MFA, Entra Password Protection & Identity Protection sind aktiv!).

### Prüfung via UI (M365 Admin Center)
- `M365 Admin Center` → *Settings → Org settings → Security & privacy → Password expiration policy*.

### Prüfung via CLI / PowerShell

```powershell
# PasswordValidityPeriodInDays für alle Domains prüfen (2147483647 = Never expire)
Get-MgDomain | Select-Object Id, PasswordValidityPeriodInDays, PasswordNotificationWindowInDays | Format-Table -AutoSize
```

---

## 3.5 Idle Session Timeout, Kalenderfreigabe, User-Owned Apps & Customer Lockbox

### Erklärung & Risiko
- **Idle Session Timeout:** Verhindert unbefugte Weiternutzung offener M365-Web-Sessions an gemeinsam genutzten oder unbeaufsichtigten Geräten.
- **Externe Kalenderfreigabe:** Wenn Kalenderdetails (Betreff, Teilnehmer, Ort) standardmäßig anonym oder extern geteilt werden können, fließen vertrauliche Geschäftsinformationen (z. B. M&A-Termine, Kundenbeziehungen) ab.
- **User-Owned Apps / Integrated Apps / Office Store:** Ungesteuerte Drittanbieter-Add-ins erweitern die Angriffsfläche für Datenabfluss.
- **Customer Lockbox:** Erzwingt explizite Kundenfreigabe, bevor Microsoft-Support-Ingenieure im Supportfall Zugriff auf Kundendaten erhalten.

### Soll-Zustand (CIS 1.3.x / L1 & L2)
- **Idle session timeout:** Aktiviert (CIS-Empfehlung: ≤ **3 Stunden**, idealerweise 1 Stunde auf unmanaged Devices) *(L1)*.
- **Calendar sharing:** Externe anonyme Freigabe deaktiviert oder auf *Free/Busy only* begrenzt *(L2)*.
- **User-owned apps and services:** „Let users access the Microsoft 365 Store“ & „Let users start trials on behalf of your org“ deaktiviert *(L1/L2)*.
- **Integrated apps / User consent:** Eingeschränkt (siehe auch Kapitel 2.5) *(L1)*.
- **Customer Lockbox:** Aktiviert (falls E5 / Compliance-Lizenz vorhanden) *(L2)*.
- **Modern Authentication (M365 Admin):** Aktiviert für alle Protokolle *(L1)*.
- **Sway / Forms / Microsoft 365 Groups External Sharing:** Nach Bedarf restriktiv konfiguriert *(L2)*.

### Prüfung via UI (M365 Admin Center)
Alle Punkte befinden sich unter **`M365 Admin Center` → *Settings → Org settings***:
1. **Security & privacy:**
   - *Idle session timeout*
   - *Password expiration policy*
   - *Customer Lockbox*
   - *Privacy profile*
2. **Services:**
   - *Calendar* (Externe Freigabe prüfen)
   - *Modern authentication* (Exchange Online Auth-Einstellungen)
   - *User owned apps and services* (Store & Trials)
   - *Microsoft Forms* (External sharing & Phishing protection)
   - *Sway* (External sharing)
   - *Microsoft 365 Groups* (Gäste hinzufügen/zugreifen erlauben?)
   - *Microsoft 365 on the web* (Third-party storage)
3. **Integrated apps:** `M365 Admin Center` → *Settings → Integrated apps* → installierte Add-ins und Berechtigungen prüfen.

### Prüfung via CLI / PowerShell

```powershell
# 1. Idle Session Timeout (via Microsoft Graph Beta / Activity Based Timeout)
Get-MgPolicyActivityBasedTimeoutPolicy | Format-List DisplayName, Definition, IsOrganizationDefault

# 2. M365 Groups Guest Settings (Directory Settings)
Get-MgDirectorySetting | Where-Object { $_.DisplayName -eq "Group.Unified" } |
    Select-Object -ExpandProperty Values | Format-Table Name, Value

# 3. Customer Lockbox Status (Exchange Online PowerShell)
Get-OrganizationConfig | Select-Object CustomerLockboxEnabled, OAuth2ClientProfileEnabled

# 4. Externe Kalenderfreigabe (Exchange Online Sharing Policy)
Get-SharingPolicy | Select-Object Name, Enabled, Domains | Format-Table -AutoSize
```

> [!NOTE]
> Einige Einstellungen im M365 Admin Center (*Idle session timeout* UI-Toggle, *User-owned apps & services*, *Forms*, *Sway*) sind in den CIS Benchmarks als **Manual** klassifiziert und sollten direkt über die **UI** (`admin.microsoft.com → Settings → Org settings`) verifiziert und per Screenshot dokumentiert werden.
