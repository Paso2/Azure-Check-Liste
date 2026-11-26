<#
.SYNOPSIS
    Microsoft 365 & Entra ID Security Assessment - Read-Only Collector
    Orientiert am CIS Microsoft 365 Foundations Benchmark (v5.x / v6.x / v7.x)

.DESCRIPTION
    Sammelt ausschließlich lesend (Read-Only) Konfigurations-Evidenzen aus:
      - Microsoft Entra ID (Graph)
      - Microsoft 365 Admin & SharePoint Tenant Settings (via Graph!)
      - Exchange Online & Defender for Office 365
      - Microsoft Teams
      - Microsoft Intune (via Graph)
      - Optional: Microsoft Purview (Security & Compliance PowerShell)

    Optimiert für die Rollenkombination: Entra 'Global Reader' + Entra 'Security Reader'.

.EXAMPLE
    pwsh ./audit-m365-entra-reader.ps1 -TenantId "<TENANT_ID>" -UserPrincipalName "auditor@kunde.de"
    pwsh ./audit-m365-entra-reader.ps1 -TenantId "<TENANT_ID>" -UserPrincipalName "auditor@kunde.de" -IncludePurview
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [switch]$IncludePurview,
    [switch]$SkipExchange,
    [switch]$SkipTeams
)

$ErrorActionPreference = "Continue"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir = "m365-audit-output_$Timestamp"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host "[*] Ausgabe-Verzeichnis: $OutDir" -ForegroundColor Cyan

function Invoke-SafeExport {
    param(
        [string]$Name,
        [scriptblock]$Action,
        [ValidateSet("Json", "Csv")][string]$Format = "Json"
    )
    Write-Host "  [+] Prüfe: $Name" -ForegroundColor Gray
    try {
        $result = & $Action
        if ($null -ne $result) {
            if ($Format -eq "Csv") {
                $result | Export-Csv -Path (Join-Path $OutDir "$Name.csv") -NoTypeInformation -Encoding UTF8
            } else {
                $result | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $OutDir "$Name.json") -Encoding UTF8
            }
        } else {
            "[]" | Out-File -FilePath (Join-Path $OutDir "$Name.json") -Encoding UTF8
        }
    } catch {
        Write-Warning "  [!] Fehler/Fehlende Berechtigung bei '$Name': $($_.Exception.Message)"
        $_.Exception.Message | Out-File -FilePath (Join-Path $OutDir "${Name}_ERROR.txt") -Encoding UTF8
    }
}

# ==============================================================================
# 1. MICROSOFT GRAPH (Entra ID, M365, SharePoint Settings, Intune, Secure Score)
# ==============================================================================
Write-Host "`n[*] 1. Verbinde zu Microsoft Graph (Read-Only Scopes)..." -ForegroundColor Cyan
$GraphScopes = @(
    "Directory.Read.All",
    "Policy.Read.All",
    "Policy.Read.ConditionalAccess",
    "RoleManagement.Read.Directory",
    "Reports.Read.All",
    "SecurityEvents.Read.All",
    "IdentityRiskyUser.Read.All",
    "Application.Read.All",
    "UserAuthenticationMethod.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "SharePointTenantSettings.Read.All",
    "Organization.Read.All"
)

try {
    Connect-MgGraph -TenantId $TenantId -Scopes $GraphScopes -NoWelcome

    Invoke-SafeExport "01_tenant_organization" { Get-MgOrganization | Select-Object DisplayName, Id, OnPremisesSyncEnabled, OnPremisesLastSyncDateTime }
    Invoke-SafeExport "01_tenant_licenses" { Get-MgSubscribedSku | Select-Object SkuPartNumber, ConsumedUnits, @{N='Enabled';E={$_.PrepaidUnits.Enabled}} } "Csv"
    Invoke-SafeExport "01_tenant_domains" { Get-MgDomain | Select-Object Id, IsVerified, IsDefault, AuthenticationType, PasswordValidityPeriodInDays } "Csv"

    # Entra ID Security Defaults & Conditional Access
    Invoke-SafeExport "02_entra_security_defaults" { Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy }
    Invoke-SafeExport "02_entra_conditional_access_policies" { Get-MgIdentityConditionalAccessPolicy -All }
    Invoke-SafeExport "02_entra_named_locations" { Get-MgIdentityConditionalAccessNamedLocation -All }

    # Privilegierte Rollen
    Invoke-SafeExport "02_entra_active_role_assignments" {
        $roles = Get-MgDirectoryRole -All
        foreach ($role in $roles) {
            foreach ($m in (Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All)) {
                [PSCustomObject]@{
                    RoleName       = $role.DisplayName
                    MemberName     = $m.AdditionalProperties.displayName
                    UPN            = $m.AdditionalProperties.userPrincipalName
                    ObjectType     = $m.AdditionalProperties.'@odata.type'
                    OnPremSynced   = $m.AdditionalProperties.onPremisesSyncEnabled
                    AccountEnabled = $m.AdditionalProperties.accountEnabled
                }
            }
        }
    } "Csv"

    # PIM Eligible Assignments (Entra ID P2)
    Invoke-SafeExport "02_entra_pim_eligible" { Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All }

    # Auth Methods, MFA Registration & Password Protection
    Invoke-SafeExport "02_entra_auth_methods_policy" { Get-MgPolicyAuthenticationMethodPolicy }
    Invoke-SafeExport "02_entra_mfa_registration_details" { Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Select-Object UserPrincipalName, IsAdmin, IsMfaRegistered, IsMfaCapable, IsPasswordlessCapable, DefaultMfaMethod } "Csv"
    Invoke-SafeExport "02_entra_directory_settings" { Get-MgDirectorySetting -All }

    # Authorization Policy (User Settings, App Creation, Guest Access, User Consent)
    Invoke-SafeExport "02_entra_authorization_policy" { Get-MgPolicyAuthorizationPolicy }
    Invoke-SafeExport "02_entra_admin_consent_policy" { Get-MgPolicyAdminConsentRequestPolicy }
    Invoke-SafeExport "02_entra_cross_tenant_access_default" { Get-MgPolicyCrossTenantAccessPolicyDefault }

    # Public M365 Groups & Guests
    Invoke-SafeExport "03_m365_public_groups" { Get-MgGroup -Filter "groupTypes/any(c:c eq 'Unified') and visibility eq 'Public'" -All | Select-Object DisplayName, Mail, Visibility, CreatedDateTime } "Csv"
    Invoke-SafeExport "02_entra_guest_users" { Get-MgUser -Filter "userType eq 'Guest'" -Property DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime -All | Select-Object DisplayName, UserPrincipalName, AccountEnabled, CreatedDateTime } "Csv"

    # Risky Users & Microsoft Secure Score
    Invoke-SafeExport "02_entra_risky_users" { Get-MgRiskyUser -Filter "riskState eq 'atRisk'" -All | Select-Object UserPrincipalName, RiskLevel, RiskState, RiskLastUpdatedDateTime } "Csv"
    Invoke-SafeExport "04_defender_secure_score" { Get-MgSecuritySecureScore -Top 1 }

    # SharePoint Tenant Settings via Graph (funktioniert mit Global Reader!)
    Invoke-SafeExport "05_sharepoint_tenant_settings" { Get-MgAdminSharepointSetting }

    # Intune Compliance Policies & Default Non-Compliant Setting
    Invoke-SafeExport "06_intune_compliance_policies" { Get-MgDeviceManagementDeviceCompliancePolicy -All | Select-Object DisplayName, Id, LastModifiedDateTime } "Csv"
    Invoke-SafeExport "06_intune_settings_securebydefault" { Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/settings" }
} catch {
    Write-Warning "[!] Microsoft Graph Verbindung fehlgeschlagen: $($_.Exception.Message)"
}

# ==============================================================================
# 2. EXCHANGE ONLINE & DEFENDER FOR OFFICE 365
# ==============================================================================
if (-not $SkipExchange) {
    Write-Host "`n[*] 2. Verbinde zu Exchange Online PowerShell..." -ForegroundColor Cyan
    try {
        Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$false

        Invoke-SafeExport "04_exo_organization_config" { Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled, AuditDisabled, MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, CustomerLockboxEnabled, RejectDirectSend }
        Invoke-SafeExport "04_exo_transport_config" { Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled }
        Invoke-SafeExport "04_exo_accepted_domains" { Get-AcceptedDomain | Select-Object DomainName, DomainType, Default } "Csv"
        Invoke-SafeExport "04_exo_dkim_config" { Get-DkimSigningConfig | Select-Object Domain, Enabled, Status } "Csv"
        Invoke-SafeExport "04_exo_remote_domains" { Get-RemoteDomain | Select-Object Name, DomainName, AutoForwardEnabled, AutoReplyEnabled } "Csv"
        Invoke-SafeExport "04_exo_transport_rules" { Get-TransportRule | Select-Object Name, State, Priority, SetSCL, RedirectMessageTo, BlindCopyTo } "Csv"
        Invoke-SafeExport "04_exo_external_tagging" { Get-ExternalInOutlook }
        Invoke-SafeExport "04_exo_owa_policies" { Get-OwaMailboxPolicy | Select-Object Name, AdditionalStorageProvidersAvailable } "Csv"
        Invoke-SafeExport "04_exo_role_assignment_policies" { Get-RoleAssignmentPolicy | Select-Object Name, IsDefault, AssignedRoles }
        Invoke-SafeExport "04_exo_admin_audit_log_config" { Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled, AdminAuditLogEnabled, AdminAuditLogAgeLimit }
        Invoke-SafeExport "04_exo_audit_bypass" { Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object { $_.AuditBypassEnabled -eq $true } | Select-Object Name, AuditBypassEnabled } "Csv"
        Invoke-SafeExport "04_exo_mailbox_forwarding" { Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress,ForwardingAddress | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } | Select-Object DisplayName, PrimarySmtpAddress, ForwardingSmtpAddress, ForwardingAddress } "Csv"

        # Defender for Office 365 Policies
        Invoke-SafeExport "04_mdo_antiphish_policies" { Get-AntiPhishPolicy }
        Invoke-SafeExport "04_mdo_malware_policies" { Get-MalwareFilterPolicy }
        Invoke-SafeExport "04_mdo_connection_filter" { Get-HostedConnectionFilterPolicy | Select-Object Name, IPAllowList, EnableSafeList }
        Invoke-SafeExport "04_mdo_inbound_spam_policies" { Get-HostedContentFilterPolicy | Select-Object Name, IsDefault, BulkThreshold, ZapEnabled, AllowedSenders, AllowedSenderDomains }
        Invoke-SafeExport "04_mdo_outbound_spam_policies" { Get-HostedOutboundSpamFilterPolicy | Select-Object Name, AutoForwardingMode, NotifyOutboundSpam }
        Invoke-SafeExport "04_mdo_safe_attachments" { Get-SafeAttachmentPolicy }
        Invoke-SafeExport "04_mdo_atp_o365_global" { Get-AtpPolicyForO365 }
        Invoke-SafeExport "04_mdo_safe_links" { Get-SafeLinksPolicy }

        Disconnect-ExchangeOnline -Confirm:$false
    } catch {
        Write-Warning "[!] Exchange Online Verbindung fehlgeschlagen: $($_.Exception.Message)"
    }
}

# ==============================================================================
# 3. MICROSOFT TEAMS
# ==============================================================================
if (-not $SkipTeams) {
    Write-Host "`n[*] 3. Verbinde zu Microsoft Teams PowerShell..." -ForegroundColor Cyan
    try {
        Connect-MicrosoftTeams -TenantId $TenantId | Out-Null

        Invoke-SafeExport "05_teams_federation" { Get-CsTenantFederationConfiguration }
        Invoke-SafeExport "05_teams_client_config" { Get-CsTeamsClientConfiguration }
        Invoke-SafeExport "05_teams_meeting_policies" { Get-CsTeamsMeetingPolicy }
        Invoke-SafeExport "05_teams_messaging_global" { Get-CsTeamsMessagingPolicy -Identity Global }
        Invoke-SafeExport "05_teams_app_permission_policies" { Get-CsTeamsAppPermissionPolicy }

        Disconnect-MicrosoftTeams
    } catch {
        Write-Warning "[!] Microsoft Teams Verbindung fehlgeschlagen: $($_.Exception.Message)"
    }
}

# ==============================================================================
# 4. OPTIONAL: MICROSOFT PURVIEW (Security & Compliance PowerShell)
# ==============================================================================
if ($IncludePurview) {
    Write-Host "`n[*] 4. Verbinde zu Microsoft Purview (IPPSSession)..." -ForegroundColor Cyan
    try {
        Connect-IPPSSession -UserPrincipalName $UserPrincipalName -ShowBanner:$false

        Invoke-SafeExport "06_purview_dlp_policies" { Get-DlpCompliancePolicy | Select-Object Name, Enabled, Mode, ExchangeLocation, SharePointLocation, OneDriveLocation, TeamsLocation } "Csv"
        Invoke-SafeExport "06_purview_sensitivity_labels" { Get-Label | Select-Object DisplayName, Name, Disabled, Priority } "Csv"
        Invoke-SafeExport "06_purview_label_policies" { Get-LabelPolicy | Select-Object Name, Enabled, Mode } "Csv"
        Invoke-SafeExport "06_purview_audit_retention" { Get-UnifiedAuditLogRetentionPolicy | Select-Object Name, Priority, RetentionDuration, Enabled } "Csv"

        Disconnect-ExchangeOnline -Confirm:$false
    } catch {
        Write-Warning "[!] Purview (IPPSSession) Verbindung fehlgeschlagen: $($_.Exception.Message)"
    }
}

Write-Host "`n[✓] M365 & Entra ID Read-Only Assessment abgeschlossen. Evidenzen liegen in: $OutDir" -ForegroundColor Green
