# Kapitel 4: E-Mail-Sicherheit – Exchange Online & Microsoft Defender for Office 365

**CIS-Referenz:** CIS Microsoft 365 Foundations Benchmark – *Section 2: Microsoft Defender for Office 365* & *Section 6: Exchange Admin Center* (L1 & L2)  
**Primäre Portale:**
- **Exchange Admin Center (EAC):** `https://admin.exchange.microsoft.com`
- **Microsoft Defender Portal:** `https://security.microsoft.com`

**Erforderliche Rollen:**
- **Exchange Online (UI & PowerShell):** Entra `Global Reader` ✅
- **Microsoft Defender Portal (Policies & Secure Score):** Entra `Security Reader` ✅ *(Wichtig: Reiner `Global Reader` sieht im Defender-Portal u. U. keinen Secure Score; mit `Security Reader` ist alles lesbar!)*

---

## 4.1 E-Mail-Authentifizierung (DNS): SPF, DKIM & DMARC

### Erklärung & Risiko
Ohne sauber konfiguriertes **SPF**, **DKIM** und **DMARC** (mit Enforcement `p=quarantine` oder `p=reject`) können Angreifer E-Mails im Namen der Kundendomains fälschen (Spoofing / CEO-Fraud). Dies muss für **alle akzeptierten Domains** (auch geparkte Domains!) geprüft werden.

### Soll-Zustand (CIS 2.1.8 – 2.1.10 / L1)
- **SPF:** Vorhanden für jede Domain, endet auf `-all` (Hardfail) oder `~all` (Softfail) – niemals `+all` oder `?all`! Maximal 10 DNS-Lookups.
- **DKIM:** Für alle Custom Domains in Exchange Online aktiviert (`Enabled = $true`) und CNAME-Einträge im DNS veröffentlicht.
- **DMARC:** Vorhanden (`_dmarc.<domain>`), Policy `p=quarantine` oder `p=reject` (nicht nur `p=none`!), Reporting-Adresse (`rua=`) gesetzt.
- **Geparkte Domains:** `v=spf1 -all` und `v=DMARC1; p=reject;`.

### Prüfung via UI
- **DKIM:** `Microsoft Defender Portal` (`security.microsoft.com`) → *Email & collaboration → Policies & rules → Threat policies → Email authentication settings → DKIM*.
- **Accepted Domains:** `Exchange Admin Center` → *Mail flow → Accepted domains*.

### Prüfung via CLI / PowerShell & Bash

```powershell
# Alle akzeptierten Domains & DKIM-Status in Exchange Online prüfen
Get-AcceptedDomain | Select-Object DomainName, DomainType, Default | Format-Table -AutoSize
Get-DkimSigningConfig | Select-Object Domain, Enabled, Status, Selector1CNAME, Selector2CNAME | Format-Table -AutoSize

# SPF und DMARC per PowerShell für alle akzeptierten Domains abfragen
foreach ($d in (Get-AcceptedDomain).DomainName) {
    $spf = (Resolve-DnsName -Name $d -Type TXT -ErrorAction SilentlyContinue).Strings | Where-Object { $_ -like "v=spf1*" }
    $dmarc = (Resolve-DnsName -Name "_dmarc.$d" -Type TXT -ErrorAction SilentlyContinue).Strings | Where-Object { $_ -like "v=DMARC1*" }
    [PSCustomObject]@{
        Domain = $d
        SPF    = ($spf -join " | ")
        DMARC  = ($dmarc -join " | ")
    }
} | Format-Table -Wrap
```

```bash
# Alternative unter Linux/macOS für eine Domain:
DOMAIN="kunde.de"
echo "=== SPF ==="   && dig +short TXT "$DOMAIN" | grep -i spf
echo "=== DMARC ===" && dig +short TXT "_dmarc.$DOMAIN"
echo "=== DKIM ==="  && dig +short CNAME "selector1._domainkey.$DOMAIN" "selector2._domainkey.$DOMAIN"
```

---

## 4.2 Exchange Online – Härtung, Protokolle, Weiterleitungen & Auditing

### Erklärung & Risiko
Unsichere Exchange-Konfigurationen sind beliebte Persistenz- und Datenabflusskanäle: Angreifer richten automatische Weiterleitungen nach außen ein, nutzen Legacy-Protokolle wie **SMTP AUTH** zur MFA-Umgehung, missbrauchen **Direct Send** für internes Spoofing oder profitieren von zu breiten Transport-Regeln (Whitelisting).

### Soll-Zustand (CIS Section 6 / L1 & L2)
- **Modern Authentication:** Aktiviert (`OAuth2ClientProfileEnabled = $true`) *(L1)*.
- **SMTP AUTH:** Tenant-weit deaktiviert (`SmtpClientAuthenticationDisabled = $true`) *(L1)*; nur explizit notwendige Ausnahmen (z. B. alte Multifunktionsdrucker) per Mailbox-Override dokumentiert.
- **Reject Direct Send:** Aktiviert (`RejectDirectSend = $true`), sofern keine legitimen On-Prem-Relay-Geräte Direct Send benötigen *(CIS v5+ / L1)*.
- **Externe automatische Weiterleitung:** Deaktiviert in **Remote Domains** (`AutoForwardEnabled = $false`) **und** in der **Outbound Spam Policy** (`AutoForwardingMode = Off`) *(L1)*.
- **Transport Rules Audit:** Keine Mail-Flow-Regeln, die SCL auf `-1` setzen (Spam-Filter-Bypass für ganze Domains oder IPs!) *(L1)*.
- **External Email Tagging:** Aktiviert (`Set-ExternalInOutlook -Enabled $true`) *(L1)*.
- **MailTips:** Aktiviert inkl. `MailTipsExternalRecipientsTipsEnabled = $true` und `MailTipsLargeAudienceThreshold` *(L1)*.
- **Outlook on the Web (OWA) Storage Providers:** Drittanbieter-Speicher (`AdditionalStorageProvidersAvailable = $false`, z. B. Dropbox, Google Drive) deaktiviert *(L1)*.
- **Outlook Add-ins:** Benutzer dürfen nicht eigenständig beliebige Add-ins installieren (`My Custom Apps`, `My Marketplace Apps`, `My ReadWriteMailbox Apps` aus Default Role Assignment Policy entfernt) *(L1)*.
- **Mailbox & Organization Auditing:**
  - `AuditDisabled = $false` (Organization Config) *(L1)*.
  - Kein Postfach mit `AuditBypassEnabled = $true` (außer dokumentierte Service-Accounts) *(L1)*.
  - `AuditEnabled = $true` auf allen Postfächern *(L1)*.

### Prüfung via UI (Exchange Admin Center – `admin.exchange.microsoft.com`)
1. **Remote Domains:** *Mail flow → Remote domains → Default* → prüfen, ob *Allow automatic forwarding* **deaktiviert** ist.
2. **Transport Rules:** *Mail flow → Rules* → alle Regeln durchgehen (besonders achten auf: *Bypass spam filtering / SCL = -1*, Weiterleitungen, Domain-Whitelists!).
3. **Role Assignment Policies (Add-ins):** *Roles → User roles → Default Role Assignment Policy* → Berechtigungen für `My Custom Apps`, `My Marketplace Apps` prüfen.
4. **OWA Policies:** *Roles → Outlook web app policies*.
5. **Organization Settings / Direct Send:** *Settings → Mail flow* → *Reject Direct Send* prüfen.

### Prüfung via CLI / PowerShell (Exchange Online PowerShell)

```powershell
# 1. Organization Config (Modern Auth, Auditing, MailTips, Direct Send)
Get-OrganizationConfig | Select-Object `
    OAuth2ClientProfileEnabled,
    AuditDisabled,
    MailTipsAllTipsEnabled,
    MailTipsExternalRecipientsTipsEnabled,
    MailTipsGroupMetricsEnabled,
    MailTipsLargeAudienceThreshold,
    RejectDirectSend | Format-List

# 2. SMTP AUTH (Tenant-weit & Ausnahmen auf Mailbox-Ebene)
Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled
Get-CASMailbox -ResultSize Unlimited | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false } |
    Select-Object DisplayName, PrimarySmtpAddress, SmtpClientAuthenticationDisabled

# 3. Auto-Forwarding in Remote Domains & Outbound Spam Policy
Get-RemoteDomain | Select-Object Name, DomainName, AutoForwardEnabled, AutoReplyEnabled | Format-Table -AutoSize
Get-HostedOutboundSpamFilterPolicy | Select-Object Name, AutoForwardingMode, RecipientLimitExternalPerHour, ActionWhenThresholdReached | Format-Table -AutoSize

# 4. Gefährliche Transport Rules (SCL -1 / Whitelisting / externe Weiterleitung)
Get-TransportRule | Select-Object Name, State, Priority, SetSCL, RedirectMessageTo, BlindCopyTo, SenderDomainIs | Format-Table -AutoSize

# 5. External Email Tagging
Get-ExternalInOutlook | Format-List

# 6. OWA Additional Storage Providers (Dropbox/Google Drive etc.)
Get-OwaMailboxPolicy | Select-Object Name, AdditionalStorageProvidersAvailable | Format-Table -AutoSize

# 7. Outlook Add-in Berechtigungen in Role Assignment Policies
Get-RoleAssignmentPolicy | Select-Object Name, IsDefault, AssignedRoles | Format-List

# 8. Mailbox Audit Bypass & deaktiviertes Mailbox Auditing finden
Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object { $_.AuditBypassEnabled -eq $true } |
    Select-Object Name, AuditBypassEnabled
Get-EXOMailbox -ResultSize Unlimited -PropertySets Audit | Where-Object { $_.AuditEnabled -eq $false } |
    Select-Object DisplayName, PrimarySmtpAddress, AuditEnabled

# 9. Bestehende Postfach-Weiterleitungen an externe Adressen (Compliance-/Kompromittierungs-Check!)
Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress,ForwardingAddress |
    Where-Object { $_.ForwardingSmtpAddress -ne $null -or $_.ForwardingAddress -ne $null } |
    Select-Object DisplayName, PrimarySmtpAddress, ForwardingSmtpAddress, ForwardingAddress
```

---

## 4.3 Microsoft Defender for Office 365 (Anti-Phishing, Safe Links, Safe Attachments, Anti-Malware, Anti-Spam)

### Erklärung & Risiko
E-Mail bleibt der häufigste Initial-Access-Vektor (Phishing, QR-Code-Phishing, Malware-Anhänge, BEC). Fehlkonfigurierte oder fehlende Defender-for-Office-365-Policies (oder zu großzügige Allow-Lists im Connection Filter / Tenant Allow-Block List) hebeln den Schutz aus.

### Soll-Zustand (CIS Section 2 / L1 & L2)
- **Preset Security Policies:** Mindestens *Standard* (besser *Strict* für VIPs/Admins) – oder gleichwertige Custom Policies aktiv *(L1/L2)*.
- **Anti-Phishing Policy:**
  - *Phishing email threshold* mindestens **2 (Aggressive)** (CIS L1) bzw. **3** *(L2)*.
  - *Mailbox Intelligence* & *Intelligence for impersonation protection* aktiviert *(L1)*.
  - *Targeted users* (Geschäftsführung/Finanzen) und *Targeted domains* geschützt *(L1)*.
  - *Spoof intelligence* aktiviert (`EnableSpoofIntelligence = $true`) *(L1)*.
  - *First contact safety tip* aktiviert *(L1)*.
- **Anti-Malware Policy:**
  - *Common attachment types filter* aktiviert (`EnableFileFilter = $true`) inkl. umfassender Dateiendungsliste (`.exe`, `.js`, `.vbs`, `.iso`, `.lnk`, `.hta`, `.ps1`, `.bat`, `.scr`, `.cab`, `.img` etc.) *(L1)*.
  - *Zero-hour auto purge (ZAP)* für Malware aktiviert *(L1)*.
  - Admin-Benachrichtigungen für interne Malware-Sender aktiviert *(L1)*.
- **Anti-Spam & Connection Filter:**
  - **Connection Filter (`Default`):** `IPAllowList` sollte **leer** sein und `EnableSafeList = $false` (keine blinde IP-Allowlist!) *(L1)*.
  - **Inbound Anti-Spam:** Keine ganzen Domains in `AllowedSenderDomains` (Umgehung von SPF/DKIM/DMARC!), ZAP aktiviert, Bulk-Threshold ≤ 6 *(L1)*.
  - **Outbound Anti-Spam:** `AutoForwardingMode = Off`, Benachrichtigung an Admins bei geblockten Sendern (`NotifyOutboundSpam = $true`) *(L1)*.
- **Safe Attachments (erfordert Defender for O365 Plan 1/2):**
  - Aktiviert für **E-Mail** (`Action = Block`) **sowie** für **SharePoint, OneDrive & Teams** (`EnableATPForSPOTeamsODB = $true`) *(L1)*.
- **Safe Links (erfordert Defender for O365 Plan 1/2):**
  - Aktiviert für **E-Mail**, **Teams** und **Office Apps** (`EnableSafeLinksForEmail`, `EnableSafeLinksForTeams`, `EnableSafeLinksForOffice = $true`), `AllowClickThrough = $false`, `ScanUrls = $true`, `DisableUrlRewrite = $false` *(L1)*.
- **Priority Account Protection** für Führungskräfte/Admins (Plan 2) *(L2)*.
- **Microsoft Secure Score:** Überprüfen & Top-Empfehlungen dokumentieren!

### Prüfung via UI (Microsoft Defender Portal – `security.microsoft.com`)
1. **Secure Score:** *Exposure management → Exposure overview* bzw. *Microsoft Secure Score* (Score & Top-Improvement-Actions exportieren!).
2. **Threat Policies:** *Email & collaboration → Policies & rules → Threat policies*:
   - *Preset security policies*
   - *Anti-phishing*
   - *Anti-spam* (Connection filter, Inbound, Outbound)
   - *Anti-malware*
   - *Safe Attachments* (inkl. *Global settings* → SharePoint/OneDrive/Teams Toggle!)
   - *Safe Links*
   - *Tenant Allow/Block Lists* (prüfen, ob unbefristete/riskante Allow-Einträge existieren!)
3. **Priority Accounts:** *Settings → Email & collaboration → User tags → Priority account*.
4. **Defender for Cloud Apps (MDCA):** *Cloud apps → Policies → Policy management* (prüfen, ob Anomalie-/Impossible-Travel-/Mass-Download-Policies aktiv sind).

### Prüfung via CLI / PowerShell (Exchange Online PowerShell)

```powershell
# 1. Anti-Phishing Policies prüfen
Get-AntiPhishPolicy | Select-Object `
    Name, Enabled, PhishThresholdLevel,
    EnableMailboxIntelligence, EnableMailboxIntelligenceProtection,
    EnableSpoofIntelligence, EnableTargetedUserProtection, EnableTargetedDomainsProtection,
    EnableFirstContactSafetyTips, HonorDmarcPolicy | Format-List

# 2. Anti-Malware Policies prüfen
Get-MalwareFilterPolicy | Select-Object `
    Name, IsDefault, EnableFileFilter, FileTypes, ZapEnabled,
    EnableInternalSenderAdminNotifications, InternalSenderAdminAddress | Format-List

# 3. Connection Filter (IP Allowlist!) & Inbound Anti-Spam (AllowedSenderDomains!)
Get-HostedConnectionFilterPolicy | Select-Object Name, IPAllowList, EnableSafeList | Format-List
Get-HostedContentFilterPolicy | Select-Object `
    Name, IsDefault, BulkThreshold, ZapEnabled,
    AllowedSenders, AllowedSenderDomains,
    HighConfidencePhishAction, PhishSpamAction, HighConfidenceSpamAction | Format-List

# 4. Safe Attachments (E-Mail + Global Settings für SPO/OneDrive/Teams)
Get-SafeAttachmentPolicy | Select-Object Name, Enable, Action, QuarantineTag | Format-Table -AutoSize
Get-AtpPolicyForO365 | Select-Object EnableATPForSPOTeamsODB, EnableSafeDocs, AllowSafeDocsOpen | Format-List

# 5. Safe Links
Get-SafeLinksPolicy | Select-Object `
    Name, IsEnabled, EnableSafeLinksForEmail, EnableSafeLinksForTeams,
    EnableSafeLinksForOffice, AllowClickThrough, ScanUrls, EnableForInternalSenders | Format-List

# 6. Tenant Allow/Block Lists prüfen (auf gefährliche Allow-Einträge achten!)
Get-TenantAllowBlockListItems -ListType Url -Allow
Get-TenantAllowBlockListItems -ListType Sender -Allow
Get-TenantAllowBlockListSpoofItems -Action Allow
```

```powershell
# 7. Microsoft Secure Score via Microsoft Graph abrufen (erfordert SecurityEvents.Read.All)
Get-MgSecuritySecureScore -Top 1 | Select-Object CreatedDateTime, CurrentScore, MaxScore,
    @{N='Percentage';E={[math]::Round(($_.CurrentScore / $_.MaxScore) * 100, 1)}}
```
