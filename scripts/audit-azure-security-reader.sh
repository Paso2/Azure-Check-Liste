#!/usr/bin/env bash
# ==============================================================================
# Azure Security Assessment - Read-Only Collector (Security Reader / Reader)
# Orientiert am CIS Microsoft Azure Foundations Benchmark (v5.x / v6.x)
#
# Nutzung:
#   az login --tenant "<TENANT_ID>"
#   ./audit-azure-security-reader.sh
#
# Sicherheitshinweis:
#   Dieses Skript führt AUSSCHLIESSLICH lesende (GET/list/show/query) Aufrufe aus.
#   Es erkennt automatisch, ob neben 'Security Reader' auch 'Reader'-Rechte
#   vorhanden sind, und fällt andernfalls sauber auf Defender-Assessments zurück.
# ==============================================================================

set -u
set -o pipefail

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="azure-audit-output_${TIMESTAMP}"
mkdir -p "${OUT_DIR}"

echo "[*] Ausgabe-Verzeichnis: ${OUT_DIR}"

# Prüfen ob az CLI angemeldet ist
if ! az account show >/dev/null 2>&1; then
  echo "[!] Fehler: Nicht bei Azure CLI angemeldet. Bitte zuerst 'az login --tenant <TENANT_ID>' ausführen."
  exit 1
fi

run_safe() {
  local outfile="$1"
  shift
  if "$@" > "${outfile}" 2> "${outfile}.err"; then
    rm -f "${outfile}.err"
  else
    echo "    [!] Eingeschränkt / Fehler bei $(basename "${outfile}") (Details in ${outfile}.err)"
  fi
}

echo "[*] 1. Subscriptions & Management Groups sammeln..."
run_safe "${OUT_DIR}/00_subscriptions.json" az account list -o json
run_safe "${OUT_DIR}/00_management_groups.json" az account management-group list -o json

echo "[*] 2. Azure Resource Graph (funktioniert mit reinem Security Reader)..."
if az extension show --name resource-graph >/dev/null 2>&1; then
  run_safe "${OUT_DIR}/01_arg_secure_scores.json" az graph query -q "
    securityresources
    | where type == 'microsoft.security/securescores'
    | project SubscriptionId=subscriptionId, Name=name, Current=properties.score.current, Max=properties.score.max, Percentage=properties.score.percentage
  " --first 1000 -o json

  run_safe "${OUT_DIR}/01_arg_unhealthy_assessments.json" az graph query -q "
    securityresources
    | where type == 'microsoft.security/assessments'
    | where properties.status.code == 'Unhealthy'
    | project SubscriptionId=subscriptionId, Assessment=tostring(properties.displayName), Severity=tostring(properties.metadata.severity), ResourceId=tostring(properties.resourceDetails.Id)
  " --first 1000 -o json

  run_safe "${OUT_DIR}/01_arg_cis_failed_controls.json" az graph query -q "
    securityresources
    | where type == 'microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols'
    | where id has 'CIS' and properties.state == 'Failed'
    | project SubscriptionId=subscriptionId, Control=name, Description=tostring(properties.description), FailedResources=toint(properties.failedResources)
  " --first 1000 -o json
else
  echo "    [i] Extension 'resource-graph' nicht installiert. Installieren mit: az extension add --name resource-graph"
fi

# Über alle aktiven Subscriptions iterieren
SUB_IDS="$(az account list --query "[?state=='Enabled'].id" -o tsv)"

for SUB_ID in ${SUB_IDS}; do
  SUB_NAME="$(az account show --subscription "${SUB_ID}" --query name -o tsv | tr -cs 'A-Za-z0-9._-' '_')"
  SUB_DIR="${OUT_DIR}/sub_${SUB_NAME}_${SUB_ID}"
  mkdir -p "${SUB_DIR}"
  echo "[*] === Subscription: ${SUB_NAME} (${SUB_ID}) ==="

  az account set --subscription "${SUB_ID}"

  # ----------------------------------------------------------------------------
  # TEIL A: Funktioniert direkt mit Azure RBAC 'Security Reader'
  # ----------------------------------------------------------------------------
  echo "  [+] Teil A: RBAC, Policy, Defender for Cloud & Logging (Security Reader)"
  run_safe "${SUB_DIR}/rbac_privileged_assignments.json" az role assignment list --all \
    --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='User Access Administrator' || roleDefinitionName=='Contributor' || roleDefinitionName=='Role Based Access Control Administrator']" -o json
  run_safe "${SUB_DIR}/rbac_custom_roles.json" az role definition list --custom-role-only true -o json
  run_safe "${SUB_DIR}/rbac_classic_admins.json" az rest --method GET \
    --url "https://management.azure.com/subscriptions/${SUB_ID}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-07-01" -o json

  run_safe "${SUB_DIR}/defender_secure_scores.json" az security secure-scores list -o json
  run_safe "${SUB_DIR}/defender_pricings.json" az security pricing list -o json
  run_safe "${SUB_DIR}/defender_contacts.json" az security contact list -o json
  run_safe "${SUB_DIR}/defender_auto_provisioning.json" az security auto-provisioning-setting list -o json
  run_safe "${SUB_DIR}/defender_regulatory_compliance.json" az security regulatory-compliance-standards list -o json
  run_safe "${SUB_DIR}/defender_jit_policies.json" az rest --method GET \
    --url "https://management.azure.com/subscriptions/${SUB_ID}/providers/Microsoft.Security/jitNetworkAccessPolicies?api-version=2020-01-01" -o json

  run_safe "${SUB_DIR}/policy_assignments.json" az policy assignment list -o json
  run_safe "${SUB_DIR}/policy_compliance_summary.json" az policy state summarize -o json
  run_safe "${SUB_DIR}/policy_exemptions.json" az rest --method GET \
    --url "https://management.azure.com/subscriptions/${SUB_ID}/providers/Microsoft.Authorization/policyExemptions?api-version=2022-07-01-preview" -o json

  run_safe "${SUB_DIR}/logging_activity_log_alerts.json" az monitor activity-log alert list -o json
  run_safe "${SUB_DIR}/logging_log_analytics_workspaces.json" az monitor log-analytics workspace list -o json

  # ----------------------------------------------------------------------------
  # TEIL B: Direkte Ressourcen-Inspektion (benötigt zusätzlich Azure 'Reader')
  # ----------------------------------------------------------------------------
  if az storage account list --query "[0].id" -o tsv >/dev/null 2>&1; then
    echo "  [+] Teil B: Direkte Ressourcen-Inspektion (Azure Reader erkannt!)"
    run_safe "${SUB_DIR}/logging_subscription_diagnostics.json" az monitor diagnostic-settings subscription list --subscription "${SUB_ID}" -o json
    run_safe "${SUB_DIR}/network_nsgs_risky_inbound.json" az network nsg list \
      --query "[].{NSG:name, RG:resourceGroup, RiskyRules:securityRules[?direction=='Inbound' && access=='Allow' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0' || sourceAddressPrefix=='Internet')]}" -o json
    run_safe "${SUB_DIR}/network_public_ips.json" az network public-ip list -o json
    run_safe "${SUB_DIR}/network_watchers.json" az network watcher list -o json
    run_safe "${SUB_DIR}/network_app_gateways.json" az network application-gateway list -o json
    run_safe "${SUB_DIR}/network_private_endpoints.json" az network private-endpoint list -o json

    run_safe "${SUB_DIR}/storage_accounts.json" az storage account list --query "[].{Name:name, RG:resourceGroup, HTTPSOnly:enableHttpsTrafficOnly, MinTLS:minimumTlsVersion, PublicBlob:allowBlobPublicAccess, SharedKey:allowSharedKeyAccess, PublicNet:publicNetworkAccess, NetDefault:networkRuleSet.defaultAction, CrossTenant:allowCrossTenantReplication}" -o json
    run_safe "${SUB_DIR}/keyvaults.json" az keyvault list --query "[].{Name:name, RG:resourceGroup, RBAC:properties.enableRbacAuthorization, SoftDelete:properties.enableSoftDelete, PurgeProtection:properties.enablePurgeProtection, PublicNet:properties.publicNetworkAccess, NetDefault:properties.networkAcls.defaultAction}" -o json

    run_safe "${SUB_DIR}/sql_servers.json" az sql server list -o json
    run_safe "${SUB_DIR}/postgres_flexible_servers.json" az postgres flexible-server list -o json
    run_safe "${SUB_DIR}/cosmosdb_accounts.json" az cosmosdb list --query "[].{Name:name, RG:resourceGroup, DisableLocalAuth:disableLocalAuth, PublicNet:publicNetworkAccess}" -o json

    run_safe "${SUB_DIR}/compute_vms.json" az vm list --query "[].{Name:name, RG:resourceGroup, OSType:storageProfile.osDisk.osType, EncAtHost:securityProfile.encryptionAtHost, SecurityType:securityProfile.securityType, Identity:identity.type}" -o json
    run_safe "${SUB_DIR}/compute_webapps.json" az webapp list --query "[].{Name:name, RG:resourceGroup, HTTPSOnly:httpsOnly, MinTLS:siteConfig.minTlsVersion, FTPS:siteConfig.ftpsState, HTTP2:siteConfig.http20Enabled, RemoteDebug:siteConfig.remoteDebuggingEnabled, Identity:identity.type}" -o json
    run_safe "${SUB_DIR}/compute_aks.json" az aks list --query "[].{Name:name, RG:resourceGroup, EntraRBAC:aadProfile.enableAzureRbac, DisableLocalAccounts:disableLocalAccounts, PrivateCluster:apiServerAccessProfile.enablePrivateCluster, NetPolicy:networkProfile.networkPolicy}" -o json
    run_safe "${SUB_DIR}/compute_acr.json" az acr list --query "[].{Name:name, RG:resourceGroup, AdminUser:adminUserEnabled, AnonymousPull:anonymousPullEnabled, PublicNet:publicNetworkAccess}" -o json
  else
    echo "  [i] Hinweis: Kein direkter Azure 'Reader'-Zugriff erkannt – Teil B übersprungen."
    echo "      Nutze die gesammelten Defender for Cloud Assessments in '${OUT_DIR}/01_arg_unhealthy_assessments.json'."
  fi
done

echo ""
echo "[✓] Azure Read-Only Assessment abgeschlossen. Evidenzen liegen in: ${OUT_DIR}"
