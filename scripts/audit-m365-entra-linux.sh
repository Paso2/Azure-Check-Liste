#!/usr/bin/env bash
# ==============================================================================
# Microsoft 365 & Entra ID Security Assessment - Native Linux CLI Collector
# Orientiert am CIS Microsoft 365 Foundations Benchmark (v5.x / v6.x / v7.x)
#
# Voraussetzungen (Linux):
#   - az (Azure CLI) ODER m365 (@pnp/cli-microsoft365)
#   - jq, dig (dnsutils)
#   - Optional: pwsh (nur bei --with-pwsh für Exchange / Defender O365 / Teams)
#
# Nutzung:
#   # Standard (mit angemeldetem 'az login --tenant <TID> --allow-no-subscriptions'):
#   ./audit-m365-entra-linux.sh
#
#   # Mit CLI for Microsoft 365 ('m365 login' – empfohlen, falls az rest 403 liefert):
#   ./audit-m365-entra-linux.sh --tool m365
#
#   # Zusätzlich Exchange Online, Defender O365 & Teams per Linux-pwsh abrufen:
#   ./audit-m365-entra-linux.sh --tool m365 --with-pwsh --tenant "<TENANT_ID>" --upn "auditor@kunde.de"
#
# Sicherheitshinweis:
#   Dieses Skript führt AUSSCHLIESSLICH lesende (GET / dig) Abfragen aus.
# ==============================================================================

set -u
set -o pipefail

GRAPH_TOOL="az"
WITH_PWSH=0
TENANT_ID=""
UPN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tool)
      GRAPH_TOOL="${2:-az}"
      shift 2
      ;;
    --with-pwsh)
      WITH_PWSH=1
      shift
      ;;
    --tenant)
      TENANT_ID="${2:-}"
      shift 2
      ;;
    --upn)
      UPN="${2:-}"
      shift 2
      ;;
    -h|--help)
      sed -n '2,23p' "$0"
      exit 0
      ;;
    *)
      echo "[!] Unbekannte Option: $1"
      exit 1
      ;;
  esac
done

for bin in jq dig; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "[!] Fehlendes Linux-Tool: '$bin'. Installieren mit: sudo apt-get install -y jq dnsutils"
    exit 1
  fi
done

if [[ "$GRAPH_TOOL" == "m365" ]]; then
  command -v m365 >/dev/null 2>&1 || { echo "[!] 'm365' nicht gefunden (npm i -g @pnp/cli-microsoft365)"; exit 1; }
elif [[ "$GRAPH_TOOL" == "az" ]]; then
  command -v az >/dev/null 2>&1 || { echo "[!] 'az' nicht gefunden"; exit 1; }
else
  echo "[!] Ungültiges --tool '${GRAPH_TOOL}'. Erlaubt: az | m365"
  exit 1
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="m365-linux-audit_${TIMESTAMP}"
mkdir -p "${OUT_DIR}"

echo "[*] Starte M365 & Entra ID Linux-CLI-Assessment (Tool: ${GRAPH_TOOL})"
echo "[*] Ausgabe-Verzeichnis: ${OUT_DIR}"

graph_get_to_file() {
  local outfile="$1"
  local url="$2"
  echo "  [+] Graph GET: $(basename "${outfile}")"
  if [[ "$GRAPH_TOOL" == "m365" ]]; then
    if m365 request --url "${url}" --accept "application/json" --output json > "${outfile}" 2> "${outfile}.err"; then
      rm -f "${outfile}.err"
    else
      echo "      [!] Eingeschränkt / Fehler (Details in $(basename "${outfile}").err)"
    fi
  else
    if az rest --method GET --url "${url}" -o json > "${outfile}" 2> "${outfile}.err"; then
      rm -f "${outfile}.err"
    else
      echo "      [!] Eingeschränkt / 403 Scope-Limit? Tipp: '--tool m365' nutzen (Details in $(basename "${outfile}").err)"
    fi
  fi
}

# ==============================================================================
# 1. TENANT-GRUNDLAGEN (Kapitel 1 & 3)
# ==============================================================================
echo ""
echo "[*] 1. Tenant-Grundlagen, Lizenzen & Domains..."
graph_get_to_file "${OUT_DIR}/01_organization.json" "https://graph.microsoft.com/v1.0/organization"
graph_get_to_file "${OUT_DIR}/01_subscribed_skus.json" "https://graph.microsoft.com/v1.0/subscribedSkus"
graph_get_to_file "${OUT_DIR}/01_domains.json" "https://graph.microsoft.com/v1.0/domains"

# ==============================================================================
# 2. DNS-CHECK: SPF, DMARC & DKIM für alle verifizierten Domains (Kapitel 4.1)
# ==============================================================================
echo ""
echo "[*] 2. Prüfe DNS (SPF, DMARC, DKIM CNAMEs) via dig..."
DNS_OUT="${OUT_DIR}/04_dns_spf_dkim_dmarc.txt"
: > "${DNS_OUT}"
if [[ -s "${OUT_DIR}/01_domains.json" ]]; then
  jq -r '.value[]? | select(.isVerified == true) | .id' "${OUT_DIR}/01_domains.json" | while read -r DOMAIN; do
    {
      echo "=========================================="
      echo "Domain: ${DOMAIN}"
      echo "  SPF   : $(dig +short TXT "${DOMAIN}" | grep -i 'v=spf1' | tr '\n' ' ')"
      echo "  DMARC : $(dig +short TXT "_dmarc.${DOMAIN}" | grep -i 'v=DMARC1' | tr '\n' ' ')"
      echo "  DKIM1 : $(dig +short CNAME "selector1._domainkey.${DOMAIN}")"
      echo "  DKIM2 : $(dig +short CNAME "selector2._domainkey.${DOMAIN}")"
    } >> "${DNS_OUT}"
  done
  echo "  [+] Gespeichert: $(basename "${DNS_OUT}")"
fi

# ==============================================================================
# 3. MICROSOFT ENTRA ID (Kapitel 2)
# ==============================================================================
echo ""
echo "[*] 3. Microsoft Entra ID (CA, Rollen, PIM, Auth Methods, Consent, Gäste, Apps)..."
graph_get_to_file "${OUT_DIR}/02_security_defaults.json" "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
graph_get_to_file "${OUT_DIR}/02_conditional_access_policies.json" "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
graph_get_to_file "${OUT_DIR}/02_named_locations.json" "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
graph_get_to_file "${OUT_DIR}/02_directory_roles.json" "https://graph.microsoft.com/v1.0/directoryRoles"
graph_get_to_file "${OUT_DIR}/02_pim_eligible.json" "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?\$expand=roleDefinition,principal"
graph_get_to_file "${OUT_DIR}/02_pim_active.json" "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?\$expand=roleDefinition,principal"
graph_get_to_file "${OUT_DIR}/02_auth_methods_policy.json" "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
graph_get_to_file "${OUT_DIR}/02_mfa_registration_details.json" "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?\$top=999"
graph_get_to_file "${OUT_DIR}/02_group_settings_password_m365.json" "https://graph.microsoft.com/v1.0/groupSettings"
graph_get_to_file "${OUT_DIR}/02_authorization_policy.json" "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
graph_get_to_file "${OUT_DIR}/02_admin_consent_policy.json" "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy"
graph_get_to_file "${OUT_DIR}/02_cross_tenant_access_default.json" "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default"
graph_get_to_file "${OUT_DIR}/02_guest_users.json" "https://graph.microsoft.com/v1.0/users?\$filter=userType eq 'Guest'&\$select=displayName,userPrincipalName,accountEnabled,createdDateTime&\$top=999"
graph_get_to_file "${OUT_DIR}/02_app_registrations_secrets.json" "https://graph.microsoft.com/v1.0/applications?\$select=displayName,appId,passwordCredentials,keyCredentials&\$top=999"
graph_get_to_file "${OUT_DIR}/02_risky_users.json" "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?\$filter=riskState eq 'atRisk'"
graph_get_to_file "${OUT_DIR}/02_risk_detections.json" "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?\$top=50"

# Global Administrators inkl. Lizenz- & Sync-Check
if [[ -s "${OUT_DIR}/02_directory_roles.json" ]]; then
  GA_ID="$(jq -r '.value[]? | select(.displayName == "Global Administrator") | .id' "${OUT_DIR}/02_directory_roles.json" | head -n1)"
  if [[ -n "${GA_ID}" ]]; then
    graph_get_to_file "${OUT_DIR}/02_global_admins_members.json" \
      "https://graph.microsoft.com/v1.0/directoryRoles/${GA_ID}/members?\$select=displayName,userPrincipalName,assignedLicenses,onPremisesSyncEnabled,accountEnabled"
  fi
fi

# Entra ID Diagnostic Settings (ARM API, nur via az)
if command -v az >/dev/null 2>&1; then
  echo "  [+] ARM GET: 02_entra_diagnostic_settings.json"
  if az rest --method GET \
      --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" \
      -o json > "${OUT_DIR}/02_entra_diagnostic_settings.json" 2> "${OUT_DIR}/02_entra_diagnostic_settings.json.err"; then
    rm -f "${OUT_DIR}/02_entra_diagnostic_settings.json.err"
  else
    echo "      [!] Eingeschränkt (Details in 02_entra_diagnostic_settings.json.err)"
  fi
fi

# ==============================================================================
# 4. M365 ADMIN, DEFENDER SECURE SCORE, SHAREPOINT, INTUNE & PURVIEW (Kap. 3–6)
# ==============================================================================
echo ""
echo "[*] 4. M365 Admin, Secure Score, SharePoint Settings, Intune & Purview (via Graph)..."
graph_get_to_file "${OUT_DIR}/03_m365_public_groups.json" "https://graph.microsoft.com/v1.0/groups?\$filter=groupTypes/any(c:c eq 'Unified') and visibility eq 'Public'&\$select=displayName,mail,visibility,createdDateTime&\$top=999"
graph_get_to_file "${OUT_DIR}/03_m365_idle_session_timeout.json" "https://graph.microsoft.com/v1.0/policies/activityBasedTimeoutPolicies"
graph_get_to_file "${OUT_DIR}/04_defender_secure_score.json" "https://graph.microsoft.com/v1.0/security/secureScores?\$top=1"
graph_get_to_file "${OUT_DIR}/05_sharepoint_tenant_settings.json" "https://graph.microsoft.com/v1.0/admin/sharepoint/settings"
graph_get_to_file "${OUT_DIR}/05_teams_groups_inventory.json" "https://graph.microsoft.com/v1.0/groups?\$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&\$select=displayName,visibility,createdDateTime&\$top=999"
graph_get_to_file "${OUT_DIR}/06_purview_sensitivity_labels.json" "https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels"
graph_get_to_file "${OUT_DIR}/06_intune_settings_securebydefault.json" "https://graph.microsoft.com/beta/deviceManagement/settings"
graph_get_to_file "${OUT_DIR}/06_intune_compliance_policies.json" "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies"
graph_get_to_file "${OUT_DIR}/06_intune_enrollment_configs.json" "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations"
graph_get_to_file "${OUT_DIR}/06_entra_device_registration_policy.json" "https://graph.microsoft.com/v1.0/policies/deviceRegistrationPolicy"

# ==============================================================================
# 5. OPTIONAL: EXCHANGE ONLINE, DEFENDER O365 & TEAMS VIA LINUX pwsh
# ==============================================================================
if [[ "${WITH_PWSH}" -eq 1 ]]; then
  echo ""
  echo "[*] 5. Starte optionalen Linux-pwsh-Collector für Exchange Online, Defender O365 & Teams..."
  if ! command -v pwsh >/dev/null 2>&1; then
    echo "  [!] 'pwsh' ist nicht installiert. Siehe Kapitel 1.5.3 für die Linux-Installation."
  elif [[ -z "${TENANT_ID}" || -z "${UPN}" ]]; then
    echo "  [!] Für --with-pwsh bitte auch --tenant <TENANT_ID> und --upn <EMAIL> angeben."
  else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    pwsh -NoLogo -File "${SCRIPT_DIR}/audit-m365-entra-reader.ps1" -TenantId "${TENANT_ID}" -UserPrincipalName "${UPN}" -SkipGraph
  fi
fi

echo ""
echo "[✓] M365 & Entra ID Linux-CLI-Assessment abgeschlossen. Evidenzen liegen in: ${OUT_DIR}"
