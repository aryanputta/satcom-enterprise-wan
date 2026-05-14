# Architecture

## System Overview

SATCOM Enterprise WAN Integration and Telemetry Platform simulates a production enterprise deployment where a customer LAN connects through a SATCOM WAN uplink to a cloud PoP, peers via BGP, and uses an encrypted VPN tunnel for traffic isolation.

The full stack runs in Linux network namespaces on a single host, making it reproducible without physical hardware.

## Namespace Topology

```
[ns-enterprise]         [ns-ce]             [ns-satcom]          [ns-pop]           [ns-cloud]          [ns-app]
10.10.0.100/24  <--->  10.10.0.1/24    100.64.0.1/30 <---> 100.64.0.2/30  100.65.0.1/30 <---> 100.65.0.2/30  172.16.0.1/30 <---> 172.16.0.2/30  192.168.100.1/24 <---> 192.168.100.10/24
                        100.64.0.1/30       (netem: latency,                 172.16.0.1/30       192.168.100.1/24
                        [NAT, iptables,       loss, jitter,
                         WireGuard]          bandwidth)
                        BGP ASN 65001                             BGP ASN 65002
```

## Data Plane

Traffic path from enterprise to application server:

```
enterprise-lan (10.10.0.0/24)
  -> CE router (NAT MASQUERADE, iptables FORWARD)
  -> SATCOM WAN emulator (tc netem: latency + loss + jitter)
  -> Cloud PoP router (BGP route reflector)
  -> Cloud VPC router (advertises 192.168.100.0/24)
  -> Application server
```

## VPN Overlay (Optional)

When WireGuard is enabled:

```
CE wg0 (10.200.0.1) <=== encrypted UDP 51820 ===> PoP wg0 (10.200.0.2)
     |                                                      |
  10.10.0.0/24                                      192.168.100.0/24
```

MTU considerations:
- SATCOM outer MTU: 1500
- WireGuard overhead: ~80 bytes (header + auth tag + UDP/IP)
- Additional SATCOM framing: up to 140 bytes
- Safe inner MTU: 1280 (IPv6 minimum, universally safe)
- MSS clamping applied at CE to prevent silent drops

## Control Plane

BGP routing:
- CE (ASN 65001) advertises 10.10.0.0/24 to PoP via eBGP
- PoP (ASN 65002) route reflects to cloud-router via iBGP
- Cloud-router advertises 192.168.100.0/24 back to PoP
- Route-maps applied at CE and PoP boundaries for prefix filtering

## Management Plane

Telemetry stack:
- FastAPI service generates Starlink-style metrics every second
- Prometheus scrapes /metrics every 5 seconds
- Grafana renders real-time dashboard at port 3000
- All telemetry profiles match tc netem impairment states

## Failure Injection Architecture

```
inject_failure.sh <mode>
    |
    +-- tc netem (Layer 1-2 impairments)
    +-- iptables rule changes (Layer 3-4 failures)
    +-- FRR config changes (BGP failures)
    +-- ip link set mtu (MTU black hole)
    +-- ip link set down (link outage)
    |
    v
collect_diagnostics.sh
    |
    v
pcap_analyzer.py + route_analyzer.py + bgp_analyzer.py
    |
    v
root_cause_analyzer.py -> JSON output with OSI layer + confidence
```
