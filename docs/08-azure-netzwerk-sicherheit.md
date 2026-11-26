# Kapitel 8: Azure Netzwerksicherheit

**CIS-Referenz:** CIS Microsoft Azure Foundations Benchmark (v5.x / v6.x) – *Section 7: Networking Services* (L1 & L2)  
**Primäres Portal:** **Microsoft Azure Portal** (`https://portal.azure.com`)  
**Rollen-Hinweis (WICHTIG!):**
- **Direkte Prüfung (UI-Details & `az network ...`):** Erfordert zusätzlich Azure RBAC **`Reader`** (`Microsoft.Network/*/read`).
- **Mit reinem Azure `Security Reader` (ohne `Reader`):** Nutze die dokumentierten **Defender for Cloud Assessments / Azure Resource Graph (`securityresources`)** Abfragen in Abschnitt 8.6 – dort sind offene Management-Ports (RDP/SSH), fehlende DDoS-Protection, Internet-Exposition, NSG-Probleme und fehlende Private Endpoints direkt sichtbar!

---

## 8.1 Network Security Groups (NSGs) – Eingehende Management-Ports

### Erklärung & Risiko
Offene Management-Ports (**RDP 3389**, **SSH 22**) oder uneingeschränkte `Any`-/`*`-Regeln aus dem Internet (`0.0.0.0/0`, `*`, `Internet`) führen innerhalb von Minuten zu automatisierten Brute-Force- und Exploit-Angriffen auf Azure VMs.

### Soll-Zustand (CIS 7.1 – 7.4 / L1)
- **RDP (TCP 3389):** Kein `Allow` Inbound von `*`, `0.0.0.0/0`, `Internet` oder `Any` *(L1)*.
- **SSH (TCP 22):** Kein `Allow` Inbound von `*`, `0.0.0.0/0`, `Internet` oder `Any` *(L1)*.
- **UDP-Zugriff aus dem Internet:** Eingeschränkt (kein pauschales `Allow UDP *` von `Internet`) *(L1)*.
- **HTTP(S)-Zugriff (80/443) direkt auf VMs:** Möglichst nur über Load Balancer / Application Gateway / Azure Front Door mit WAF – nicht direkt auf einzelne VMs *(L1/L2)*.
- **Subnets ohne NSG:** Jedes produktive Subnet (ausgenommen spezielle Service-Subnets wie `GatewaySubnet`, `AzureFirewallSubnet`) sollte einer NSG zugeordnet sein.

### Prüfung via UI (Azure Portal)
- *Network security groups* → jede NSG öffnen → *Settings → Inbound security rules*.
- Besonders achten auf: **Source = Any / Internet**, **Destination Port = 22, 3389, *, 0-65535**, **Action = Allow** (Warndreieck im Portal!).
- Zusätzlich: *Virtual networks* → *Subnets* → prüfen, ob jedes Subnet eine NSG verknüpft hat.

### Prüfung via CLI (erfordert Azure `Reader`)

```bash
# Alle Inbound-Allow-Regeln aus dem Internet / Any über alle NSGs hinweg finden
az network nsg list --query "[].{NSG:name, RG:resourceGroup, RiskyRules:securityRules[?direction=='Inbound' && access=='Allow' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0' || sourceAddressPrefix=='Internet' || sourceAddressPrefix=='<nw>/0')]}" -o json

# Kompakt als Tabelle (Ports & Quellen anzeigen)
az network nsg list --query "[].securityRules[?direction=='Inbound' && access=='Allow' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0' || sourceAddressPrefix=='Internet')].{Rule:name, Priority:priority, Proto:protocol, Source:sourceAddressPrefix, DestPort:destinationPortRange, DestPorts:destinationPortRanges}" -o table

# Subnets OHNE zugeordnete NSG finden
az network vnet list --query "[].{VNet:name, SubnetsWithoutNSG:subnets[?networkSecurityGroup==null].name}" -o json
```

---

## 8.2 Public IP-Adressen, Azure Bastion & Just-in-Time (JIT) VM Access

### Erklärung & Risiko
Jede Public IP-Adresse vergrößert die direkte Internet-Angriffsfläche. Administrativer Zugriff auf VMs sollte **niemals** über direkte Public IPs erfolgen, sondern über **Azure Bastion**, **Private VPN/ExpressRoute** oder **Defender for Cloud Just-in-Time (JIT) VM Access**.

### Soll-Zustand (CIS 7.6 – 7.9 / L1 & L2)
- Inventar aller **Public IP-Adressen**: Jede öffentliche IP muss begründet sein; VMs haben idealerweise **keine** direkte Public IP *(L1)*.
- **Azure Bastion** (oder gleichwertiges Jump-Host-/Private-Access-Konzept) für administrativen VM-Zugriff im Einsatz *(L2)*.
- **Just-in-Time (JIT) VM Access** aktiviert (Teil von Defender for Servers Plan 2), falls Management-Ports temporär geöffnet werden müssen *(L2)*.
- **Public IP SKU:** `Standard` (Basic SKU ist deprecated/unsicherer, da standardmäßig „open by default“ ohne NSG!).

### Prüfung via UI (Azure Portal)
- *Public IP addresses* → komplette Liste prüfen (SKU, zugeordnete Ressource, IP-Adresse).
- *Bastions* → prüfen, ob Azure Bastion in Hub-VNets bereitgestellt ist.
- *Microsoft Defender for Cloud → Workload protections → Just-in-time VM access* *(mit `Security Reader` lesbar!)*.

### Prüfung via CLI

```bash
# Alle Public IPs inkl. SKU und zugeordneter Ressource (erfordert Azure Reader)
az network public-ip list \
  --query "[].{Name:name, RG:resourceGroup, IP:ipAddress, SKU:sku.name, AssociatedTo:ipConfiguration.id}" -o table

# Azure Bastion Hosts auflisten (erfordert Azure Reader)
az network bastion list --query "[].{Name:name, RG:resourceGroup, SKU:sku.name}" -o table

# Just-in-Time (JIT) VM Access Policies (funktioniert mit Security Reader!)
SUB_ID=$(az account show --query id -o tsv)
az rest --method GET \
  --url "https://management.azure.com/subscriptions/${SUB_ID}/providers/Microsoft.Security/jitNetworkAccessPolicies?api-version=2020-01-01" \
  --query "value[].{Name:name, VMs:properties.virtualMachines[].id}" -o json
```

---

## 8.3 Network Watcher & VNet Flow Logs (Nachfolger von NSG Flow Logs)

### Erklärung & Risiko
Ohne Netzwerk-Flow-Logs lassen sich Lateral Movement, Command-&-Control-Traffic oder Datenabfluss im Vorfall nicht rekonstruieren. **Wichtig:** Klassische *NSG Flow Logs* wurden von Microsoft abgekündigt (Retirement); der aktuelle CIS-Standard fordert **VNet Flow Logs** (mit Traffic Analytics).

### Soll-Zustand (CIS 7.5 – 7.7 / L1 & L2)
- **Network Watcher** ist in allen genutzten Azure-Regionen aktiviert *(L1)*.
- **VNet Flow Logs** sind für produktive VNets aktiviert mit einer Aufbewahrungsdauer von **≥ 90 Tagen** *(L1/L2)*.
- **Traffic Analytics** (Log Analytics Anbindung) aktiviert *(L2)*.

### Prüfung via UI (Azure Portal)
- *Network Watcher → Overview* (Regionen-Status prüfen).
- *Network Watcher → Logs → Flow logs* → prüfen, ob VNet Flow Logs aktiv sind, Aufbewahrung ≥ 90 Tage und Traffic Analytics aktiviert ist.

### Prüfung via CLI (erfordert Azure `Reader`)

```bash
# Network Watcher Status pro Region
az network watcher list --query "[].{Name:name, Location:location, State:provisioningState}" -o table

# Flow Logs für eine Region prüfen (z. B. westeurope / germanywestcentral)
az network watcher flow-log list --location westeurope \
  --query "[].{Name:name, Enabled:enabled, RetentionDays:retentionPolicy.days, Target:targetResourceId}" -o table
```

---

## 8.4 Perimeter-Schutz: WAF, Application Gateway, Front Door, Azure Firewall & DDoS Protection

### Erklärung & Risiko
Internetexponierte Webanwendungen ohne Web Application Firewall (WAF im Modus **Prevention**, nicht nur *Detection*!) sind anfällig für OWASP-Top-10-Angriffe (SQLi, XSS, RCE). Veraltete TLS-Versionen (< 1.2) gefährden die Transportverschlüsselung.

### Soll-Zustand (CIS 7.8 – 7.15 / L1 & L2)
- **WAF (Application Gateway / Azure Front Door):** Aktiviert im Modus **Prevention** mit aktuellem Regelwerk (OWASP DRS 2.1 / CRS 3.2+), `RequestBodyCheck = true` *(L1/L2)*.
- **TLS Policy:** Mindestversion **TLS 1.2** (oder TLS 1.3), HTTP-to-HTTPS-Redirect aktiv *(L1)*.
- **DDoS Network Protection (Standard):** Aktiviert auf VNets mit geschäftskritischen Public IPs *(L2)*.
- **Private Endpoints / Private Link:** Für PaaS-Dienste (Storage, Key Vault, SQL, ACR, App Service) genutzt statt öffentlicher Endpunkte *(L1/L2)*.
- **VNet Peering & Routing:** Hub-Spoke-Architektur mit zentraler Egress-Kontrolle (Azure Firewall / NVA) prüfen.

### Prüfung via UI (Azure Portal)
- *Web Application Firewall policies (WAF)* → Modus (`Prevention` vs. `Detection`), Regelwerk & Zuordnungen prüfen.
- *Application gateways* / *Front Door and CDN profiles* → SSL/TLS Policy & WAF-Verknüpfung prüfen.
- *DDoS protection plans* → zugeordnete VNets prüfen.
- *Private Link Center → Private endpoints* → prüfen, ob kritische PaaS-Dienste privat angebunden sind.

### Prüfung via CLI (erfordert Azure `Reader`)

```bash
# Application Gateways & WAF / TLS prüfen
az network application-gateway list \
  --query "[].{Name:name, RG:resourceGroup, SKU:sku.name, WAFEnabled:webApplicationFirewallConfiguration.enabled, WAFMode:webApplicationFirewallConfiguration.firewallMode, MinTLS:sslPolicy.minProtocolVersion}" -o table

# WAF Policies (Front Door & App Gateway)
az network application-gateway waf-policy list \
  --query "[].{Name:name, RG:resourceGroup, Mode:policySettings.mode, State:policySettings.state}" -o table

# DDoS Protection Plans
az network ddos-protection list --query "[].{Name:name, RG:resourceGroup, VNets:virtualNetworks[].id}" -o json

# Private Endpoints Inventar
az network private-endpoint list --query "[].{Name:name, RG:resourceGroup, Connections:privateLinkServiceConnections[].privateLinkServiceId}" -o table
```

---

## 8.5 Workaround bei reinem Azure `Security Reader` (ohne Azure `Reader`)

Falls du in Azure **ausschließlich `Security Reader`** besitzt und die obigen `az network`-Befehle mit `AuthorizationFailed` scheitern, prüfst du die Netzwerksicherheit über **Microsoft Defender for Cloud Assessments** via Azure Resource Graph (`securityresources`):

```bash
# Funktioniert mit reinem Azure Security Reader!
az graph query -q "
securityresources
| where type == 'microsoft.security/assessments'
| where properties.status.code == 'Unhealthy'
| where properties.displayName has_any ('network', 'port', 'NSG', 'Internet', 'firewall', 'DDoS', 'private', 'management', 'Bastion', 'WAF', 'TLS')
| project SubscriptionId=subscriptionId,
          Assessment=tostring(properties.displayName),
          Severity=tostring(properties.metadata.severity),
          ResourceId=tostring(properties.resourceDetails.Id)
| order by Severity desc
" --first 200 -o table
```

> [!NOTE]
> Die gleiche Information findest du in der UI unter **`Azure Portal` → *Microsoft Defender for Cloud → Recommendations*** (Filter: *Tactic / Category = Secure management ports, Restrict unauthorized network access, Enable encryption in transit*).
