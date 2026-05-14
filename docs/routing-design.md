# Routing Design

## IP Address Plan

| Segment | Subnet | Description |
|---------|--------|-------------|
| Enterprise LAN | 10.10.0.0/24 | Customer internal network |
| CE-to-SATCOM transit | 100.64.0.0/30 | WAN uplink (IANA CGNAT range) |
| SATCOM-to-PoP transit | 100.65.0.0/30 | Cloud-facing WAN link |
| PoP-to-Cloud transit | 172.16.0.0/30 | Private interconnect |
| Cloud VPC | 192.168.100.0/24 | Application server subnet |
| WireGuard overlay | 10.200.0.0/30 | Encrypted tunnel addresses |

Transit links use /30 subnets (4 addresses, 2 usable) — the minimum practical allocation for point-to-point links, matching real carrier provisioning practice.

100.64.0.0/10 is the IANA CGNAT range (RFC 6598). Using it here simulates SATCOM providers that assign CGNAT addresses on the WAN side, which affects inbound connectivity and VPN NAT traversal.

## BGP Design

### Autonomous System Numbers

| Router | ASN | Role |
|--------|-----|------|
| CE router | 65001 | Customer AS |
| Cloud PoP | 65002 | Provider/cloud AS |
| Cloud VPC router | 65002 | iBGP within cloud AS |

ASN 65001 and 65002 are private ASNs (RFC 6996, range 64512-65534).

### Peering Relationships

```
CE (AS65001) ←— eBGP —→ PoP (AS65002)
PoP (AS65002) ←— iBGP —→ Cloud-Router (AS65002)
```

eBGP (external BGP): peers in different ASes. Different AS means route advertisements are accepted or rejected based on route-maps and prefix-lists.

iBGP (internal BGP): peers in same AS. Requires either full mesh or route reflector. This lab uses the PoP as a route reflector for the cloud-router.

### Route Advertisement

**CE advertises:**
- `10.10.0.0/24` — customer LAN prefix
- Community: `65001:100` — marks customer-originated routes

**Cloud-router advertises:**
- `192.168.100.0/24` — VPC application subnet

**PoP redistributes:**
- Reflects cloud-router routes to CE via eBGP
- Reflects CE routes to cloud-router via iBGP

### Route-Map Policy

CE outbound to PoP:
```
route-map EXPORT-TO-POP permit 10
  match ip address prefix-list CUSTOMER-LAN
  set community 65001:100
```

Only the customer LAN prefix is exported. CE does not advertise transit or other routes.

CE inbound from PoP:
```
route-map IMPORT-FROM-POP permit 10
  set local-preference 100
```

Local-preference of 100 is the BGP default. Higher = preferred in multi-exit scenarios.

### BGP Timer Tuning for SATCOM

Default BGP timers are designed for stable terrestrial links:
- Keepalive: 60s
- Hold timer: 180s

SATCOM links experience frequent brief outages (beam handoff, weather). Default hold timer means 180s routing blackout per event.

Recommended for SATCOM:
```
neighbor 100.65.0.2 timers 10 30
```

Hold timer 30s = maximum 30s blackout on link failure. Keepalive 10s = BGP sends a keepalive every 10s to confirm session is live.

For production SATCOM deployment, add BFD (Bidirectional Forwarding Detection) alongside BGP for sub-second failure detection without relying on BGP hold timers.

## Static Routing (Before BGP)

Initial setup uses static routes at each namespace. BGP is added on top, and BGP-learned routes override static routes based on administrative distance:

| Protocol | Administrative Distance (Cisco convention) |
|----------|-------------------------------------------|
| Connected | 0 |
| Static | 1 |
| eBGP | 20 |
| iBGP | 200 |

Lower AD = more preferred. Static routes (AD 1) win over eBGP (AD 20) unless `ip route 192.168.100.0/24 ... distance 250` is explicitly set higher.

In this lab, static routes are the fallback. BGP routes are preferred when the session is up.

## NAT Design

### MASQUERADE at CE

The CE router performs source NAT for all LAN traffic exiting the WAN interface:

```bash
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
```

`MASQUERADE` differs from `SNAT`: it dynamically uses the current WAN interface IP. This handles SATCOM scenarios where the WAN IP may change during beam handoff without requiring NAT rule updates.

### NAT Implications for Inbound Services

MASQUERADE is unidirectional: outbound sessions are NATted and tracked, inbound connections to the LAN are not possible without explicit port forwarding.

This is the default SATCOM enterprise deployment model. To expose internal services (VPN server, management access), either:
1. Host the service at the cloud PoP (outside NAT) and access it from LAN
2. Add DNAT rules: `iptables -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to 10.10.0.50`

### CGNAT Behavior

When SATCOM providers use CGNAT (100.64.0.0/10), the CE is itself behind NAT. This means:
- CE's "public" IP is actually a CGNAT address
- VPN must use NAT traversal (WireGuard handles this natively)
- Inbound port-forwarding at CE does not work through CGNAT
- Solutions: VPN connects outbound to cloud PoP, or use STUN/TURN

## Route Verification Commands

```bash
# Check routing table at CE
sudo ip netns exec ns-ce ip route show

# Check BGP routes specifically
sudo ip netns exec ns-ce ip route show proto bgp

# Check if BGP learned the cloud VPC route
sudo ip netns exec ns-ce ip route show 192.168.100.0/24

# Check routing in all namespaces
for ns in ns-enterprise ns-ce ns-satcom ns-pop ns-cloud ns-app; do
    echo "=== $ns ==="; sudo ip netns exec $ns ip route show
done

# Traceroute to verify path
sudo ip netns exec ns-enterprise traceroute -n 192.168.100.10
```
