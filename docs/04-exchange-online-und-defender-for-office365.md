# Kapitel 4: E-Mail-Sicherheit – Exchange Online & Microsoft Defender for Office 365

**CIS-Referenz:** CIS Microsoft 365 Foundations Benchmark – *Section 2: Microsoft Defender for Office 365* & *Section 6: Exchange Admin Center* (L1 & L2)  
**Primäre Portale:**
- **Exchange Admin Center (EAC):** `https://admin.exchange.microsoft.com`
- **Microsoft Defender Portal:** `https://security.microsoft.com`

**Erforderliche Rollen:**
- **Exchange Online:** Entra `Global Reader` ✅
- **Microsoft Defender Portal (Policies & Secure Score):** Entra `Security Reader` ✅ *(Kombination beider Rollen erforderlich, da reiner `Global Reader` im Defender-Portal u. U. keinen Secure Score sieht!)*

> [!NOTE]
> **Linux-CLI-Status für Kapitel 4:**
> - **DNS (SPF, DKIM, DMARC) & Microsoft Secure Score:** 100 % nativ unter Linux mit **`az rest`**, **`dig`** und **`jq`**!
> - **Exchange Online & Defender for Office 365 Policies:** Microsoft stellt für Exchange-Admin-Policies (`Get-TransportRule`, `Get-RemoteDomain`, `Get-AntiPhishPolicy`, `Get-SafeLinksPolicy` etc.) **keine öffentliche Graph-REST-API / `az`-CLI** bereit. Das offizielle REST-basierte `ExchangeOnlineManagement`-Modul (v3.x) läuft jedoch **nativ unter Linux via `pwsh`** (inkl. `-Device` Login für SSH/Headless-Terminals) und lässt sich direkt aus Bash aufrufen!

---

## 4.1 E-Mail-Authentifizierung (DNS): SPF, DKIM & DMARC

### Erklärung & Risiko
Ohne sauber konfiguriertes **SPF**, **DKIM** und **DMARC** (mit Enforcement `p=quarantine` oder `p=reject`) können Angreifer E-Mails im Namen der Kundendomains fälschen (Spoofing / CEO-Fraud). Dies muss für **alle akzeptierten Domains** (auch geparkte Domains!) geprüft werden.

### Soll-Zustand (CIS 2.1.8 – 2.1.10 / L1)
- **SPF:** Vorhanden für jede Domain, endet auf `-all` (Hardfail) oder `~all` (Softfail) – niemals `+all` oder `?all`! Maximal 10 DNS-Lookups.
- **DKIM:** Für alle Custom Domains in Exchange Online aktiviert (`Enabled = true`) und CNAME-Einträge (`selector1._domainkey`, `selector2._domainkey`) im DNS veröffentlicht.
- **DMARC:** Vorhanden (`_dmarc.<domain>`), Policy `p=quarantine` oder `p=reject` (nicht nur `p=none`!), Reporting-Adresse (`rua=`) gesetzt.
- **Geparkte Domains:** `v=spf1 -all` und `v=DMARC1; p=reject;`.

### Prüfung via UI
- **DKIM:** `Microsoft Defender Portal` (`security.microsoft.com`) → *Email & collaboration → Policies & rules → Threat policies → Email authentication settings → DKIM*.
- **Accepted Domains:** `Exchange Admin Center` → *Mail flow → Accepted domains*.

### Prüfung via Linux CLI (`az rest` + `dig` – 100 % nativ unter Linux!)

```bash
# Alle verifizierten Tenant-Domains aus Entra ID holen und SPF, DMARC & DKIM-CNAMEs automatisch via dig prüfen!
az rest --method GET --url "https://graph.microsoft.com/v1.0/domains" \
  --query "value[?isVerified==\`true\`].id" -o tsv \
| while read -r DOMAIN; do
    echo "=========================================="
    echo "Domain: ${DOMAIN}"
    echo "  SPF   : $(dig +short TXT "${DOMAIN}" | grep -i 'v=spf1' | tr '\n' ' ')"
    echo "  DMARC : $(dig +short TXT "_dmarc.${DOMAIN}" | grep -i 'v=DMARC1' | tr '\n' ' ')"
    echo "  DKIM1 : $(dig +short CNAME "selector1._domainkey.${DOMAIN}")"
    echo "  DKIM2 : $(dig +short CNAME "selector2._domainkey.${DOMAIN}")"
done
```

```bash
# Ergänzend: Aktivierten DKIM-Signing-Status in Exchange Online prüfen (Linux pwsh):
pwsh -NoLogo -Command '
  Connect-ExchangeOnline -Device -UserPrincipalName "auditor@kunde.de" -ShowBanner:$false
  Get-AcceptedDomain | Select-Object DomainName, DomainType, Default | Format-Table -AutoSize
  Get-DkimSigningConfig | Select-Object Domain, Enabled, Status, Selector1CNAME, Selector2CNAME | Format-Table -AutoSize
  Disconnect-ExchangeOnline -Confirm:$false
'
```

---

## 4.2 Exchange Online – Härtung, Protokolle, Weiterleitungen & Auditing

### Erklärung & Risiko
Unsichere Exchange-Konfigurationen sind beliebte Persistenz- und Datenabflusskanäle: Angreifer richten automatische Weiterleitungen nach außen ein, nutzen Legacy-Protokolle wie **SMTP AUTH** zur MFA-Umgehung, missbrauchen **Direct Send** für internes Spoofing oder profitieren von zu breiten Transport-Regeln (Whitelisting).

### Soll-Zustand (CIS Section 6 / L1 & L2)
- **Modern Authentication:** Aktiviert (`OAuth2ClientProfileEnabled = true`) *(L1)*.
- **SMTP AUTH:** Tenant-weit deaktiviert (`SmtpClientAuthenticationDisabled = true`) *(L1)*; nur explizit notwendige Ausnahmen per Mailbox-Override dokumentiert.
- **Reject Direct Send:** Aktiviert (`RejectDirectSend = true`), sofern keine legitimen On-Prem-Relay-Geräte Direct Send benötigen *(CIS v5+ / L1)*.
- **Externe automatische Weiterleitung:** Deaktiviert in **Remote Domains** (`AutoForwardEnabled = false`) **und** in der **Outbound Spam Policy** (`AutoForwardingMode = Off`) *(L1)*.
- **Transport Rules Audit:** Keine Mail-Flow-Regeln, die SCL auf `-1` setzen (Spam-Filter-Bypass für ganze Domains oder IPs!) *(L1)*.
- **External Email Tagging:** Aktiviert (`Set-ExternalInOutlook -Enabled $true`) *(L1)*.
- **MailTips:** Aktiviert inkl. `MailTipsExternalRecipientsTipsEnabled = true` *(L1)*.
- **OWA Storage Providers:** Drittanbieter-Speicher (`AdditionalStorageProvidersAvailable = false`) deaktiviert *(L1)*.
- **Outlook Add-ins:** `My Custom Apps`, `My Marketplace Apps`, `My ReadWriteMailbox Apps` aus Default Role Assignment Policy entfernt *(L1)*.
- **Mailbox & Organization Auditing:** `AuditDisabled = false`, kein unerlaubtes `AuditBypassEnabled = true`, `AuditEnabled = true` auf allen Postfächern *(L1)*.

### Prüfung via UI (Exchange Admin Center – `admin.exchange.microsoft.com`)
1. **Remote Domains:** *Mail flow → Remote domains → Default* → *Allow automatic forwarding* muss **aus** sein.
2. **Transport Rules:** *Mail flow → Rules* → alle Regeln prüfen (*Bypass spam filtering / SCL = -1*, Weiterleitungen, Domain-Whitelists!).
3. **Role Assignment Policies (Add-ins):** *Roles → User roles → Default Role Assignment Policy*.
4. **OWA Policies:** *Roles → Outlook web app policies*.
5. **Organization Settings / Direct Send:** *Settings → Mail flow* → *Reject Direct Send*.

### Prüfung via Linux CLI *(via Linux `pwsh` – direkt aus Bash aufrufbar)*

```bash
# Einmalige Exchange Online Read-Only-Prüfung unter Linux (alle CIS Section 6 Checks in einer Session!)
pwsh -NoLogo -Command '
  Connect-ExchangeOnline -Device -UserPrincipalName "auditor@kunde.de" -ShowBanner:$false

  Write-Host "`n=== 1. Organization Config (Modern Auth, Audit, MailTips, Direct Send) ==="
  Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled, AuditDisabled, MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, MailTipsGroupMetricsEnabled, MailTipsLargeAudienceThreshold, RejectDirectSend | Format-List

  Write-Host "=== 2. SMTP AUTH (Tenant & Ausnahmen) ==="
  Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled | Format-List
  Get-CASMailbox -ResultSize Unlimited | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false } | Select-Object DisplayName, PrimarySmtpAddress, SmtpClientAuthenticationDisabled | Format-Table -AutoSize

  Write-Host "=== 3. Auto-Forwarding (Remote Domains & Outbound Spam) ==="
  Get-RemoteDomain | Select-Object Name, DomainName, AutoForwardEnabled, AutoReplyEnabled | Format-Table -AutoSize
  Get-HostedOutboundSpamFilterPolicy | Select-Object Name, AutoForwardingMode, RecipientLimitExternalPerHour, ActionWhenThresholdReached | Format-Table -AutoSize

  Write-Host "=== 4. Transport Rules (SCL -1 / Whitelisting / Weiterleitung) ==="
  Get-TransportRule | Select-Object Name, State, Priority, SetSCL, RedirectMessageTo, BlindCopyTo, SenderDomainIs | Format-Table -AutoSize

  Write-Host "=== 5. External Email Tagging & OWA Storage & Role Assignment Policies ==="
  Get-ExternalInOutlook | Format-List
  Get-OwaMailboxPolicy | Select-Object Name, AdditionalStorageProvidersAvailable | Format-Table -AutoSize
  Get-RoleAssignmentPolicy | Select-Object Name, IsDefault, AssignedRoles | Format-List

  Write-Host "=== 6. Mailbox Audit Bypass & deaktiviertes Auditing ==="
  Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object { $_.AuditBypassEnabled -eq $true } | Select-Object Name, AuditBypassEnabled | Format-Table -AutoSize
  Get-EXOMailbox -ResultSize Unlimited -PropertySets Audit | Where-Object { $_.AuditEnabled -eq $false } | Select-Object DisplayName, PrimarySmtpAddress, AuditEnabled | Format-Table -AutoSize

  Write-Host "=== 7. Bestehende Postfach-Weiterleitungen ==="
  Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress,ForwardingAddress | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } | Select-Object DisplayName, PrimarySmtpAddress, ForwardingSmtpAddress, ForwardingAddress | Format-Table -AutoSize

  Disconnect-ExchangeOnline -Confirm:$false
'
```

---

## 4.3 Microsoft Defender for Office 365 (Anti-Phishing, Safe Links, Safe Attachments, Anti-Malware, Anti-Spam)

### Erklärung & Risiko
E-Mail bleibt der häufigste Initial-Access-Vektor (Phishing, Malware-Anhänge, BEC). Fehlkonfigurierte Defender-for-Office-365-Policies oder breite Allow-Lists im Connection Filter / Tenant Allow-Block List hebeln den Schutz aus.

### Soll-Zustand (CIS Section 2 / L1 & L2)
- **Preset Security Policies:** Mindestens *Standard* (besser *Strict* für VIPs/Admins) – oder gleichwertige Custom Policies *(L1/L2)*.
- **Anti-Phishing Policy:** Threshold ≥ **2** *(L1)* bzw. **3** *(L2)*, Mailbox Intelligence & Impersonation Protection aktiv, Targeted Users & Domains geschützt, Spoof Intelligence & First Contact Safety Tip aktiv *(L1)*.
- **Anti-Malware Policy:** Common Attachment Types Filter aktiv (`.exe`, `.js`, `.vbs`, `.iso`, `.lnk`, `.hta`, `.ps1`, `.bat`, `.scr` etc.), ZAP aktiv, Admin-Benachrichtigungen für interne Malware-Sender aktiv *(L1)*.
- **Anti-Spam & Connection Filter:** `IPAllowList` leer, `EnableSafeList = false`, keine ganzen Domains in `AllowedSenderDomains`, ZAP aktiv, Bulk-Threshold ≤ 6 *(L1)*.
- **Safe Attachments (Plan 1/2):** Aktiv für E-Mail (`Action = Block`) **und** für SharePoint/OneDrive/Teams (`EnableATPForSPOTeamsODB = true`) *(L1)*.
- **Safe Links (Plan 1/2):** Aktiv für E-Mail, Teams & Office Apps, `AllowClickThrough = false`, `ScanUrls = true` *(L1)*.
- **Priority Account Protection** (Plan 2) & **Defender for Cloud Apps (MDCA)** aktiv *(L2)*.

### Prüfung via UI (Microsoft Defender Portal – `security.microsoft.com`)
1. **Secure Score:** *Exposure management → Exposure overview* bzw. *Microsoft Secure Score* (Score & Top-Improvement-Actions exportieren!).
2. **Threat Policies:** *Email & collaboration → Policies & rules → Threat policies* → *Preset security policies*, *Anti-phishing*, *Anti-spam*, *Anti-malware*, *Safe Attachments* (inkl. *Global settings*!), *Safe Links*, *Tenant Allow/Block Lists*.
3. **Priority Accounts:** *Settings → Email & collaboration → User tags → Priority account*.
4. **Defender for Cloud Apps:** *Cloud apps → Policies → Policy management*.

### Prüfung via Linux CLI

```bash
# 1. Microsoft Secure Score nativ per Linux CLI (Microsoft Graph REST!)
#    (Bei 403 mit az rest -> 'm365 request --url ... --output json' nutzen)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/security/secureScores?\$top=1" -o json \
| jq '.value[0] | {
    date: .createdDateTime,
    currentScore: .currentScore,
    maxScore: .maxScore,
    percentage: (((.currentScore / .maxScore) * 1000 | round) / 10)
  }'
```

```bash
# 2. Alle Defender for Office 365 Policies in einer Linux-pwsh-Session abrufen:
pwsh -NoLogo -Command '
  Connect-ExchangeOnline -Device -UserPrincipalName "auditor@kunde.de" -ShowBanner:$false

  Write-Host "`n=== Anti-Phishing ==="
  Get-AntiPhishPolicy | Select-Object Name, Enabled, PhishThresholdLevel, EnableMailboxIntelligence, EnableMailboxIntelligenceProtection, EnableSpoofIntelligence, EnableTargetedUserProtection, EnableTargetedDomainsProtection, EnableFirstContactSafetyTips, HonorDmarcPolicy | Format-List

  Write-Host "=== Anti-Malware ==="
  Get-MalwareFilterPolicy | Select-Object Name, IsDefault, EnableFileFilter, FileTypes, ZapEnabled, EnableInternalSenderAdminNotifications, InternalSenderAdminAddress | Format-List

  Write-Host "=== Connection Filter & Inbound Anti-Spam ==="
  Get-HostedConnectionFilterPolicy | Select-Object Name, IPAllowList, EnableSafeList | Format-List
  Get-HostedContentFilterPolicy | Select-Object Name, IsDefault, BulkThreshold, ZapEnabled, AllowedSenders, AllowedSenderDomains, HighConfidencePhishAction, PhishSpamAction | Format-List

  Write-Host "=== Safe Attachments & Global SPO/Teams/ODB ==="
  Get-SafeAttachmentPolicy | Select-Object Name, Enable, Action, QuarantineTag | Format-Table -AutoSize
  Get-AtpPolicyForO365 | Select-Object EnableATPForSPOTeamsODB, EnableSafeDocs, AllowSafeDocsOpen | Format-List

  Write-Host "=== Safe Links ==="
  Get-SafeLinksPolicy | Select-Object Name, IsEnabled, EnableSafeLinksForEmail, EnableSafeLinksForTeams, EnableSafeLinksForOffice, AllowClickThrough, ScanUrls, EnableForInternalSenders | Format-List

  Write-Host "=== Tenant Allow/Block Lists (Allow-Eintraege!) ==="
  Get-TenantAllowBlockListItems -ListType Url -Allow | Format-Table -AutoSize
  Get-TenantAllowBlockListItems -ListType Sender -Allow | Format-Table -AutoSize
  Get-TenantAllowBlockListSpoofItems -Action Allow | Format-Table -AutoSize

  Disconnect-ExchangeOnline -Confirm:$false
'
```
