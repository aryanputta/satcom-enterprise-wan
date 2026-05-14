#!/usr/bin/env bash
# Remove all lab namespaces and associated veth pairs
set -uo pipefail

for ns in ns-enterprise ns-ce ns-satcom ns-pop ns-cloud ns-app; do
    if ip netns list 2>/dev/null | grep -q "^$ns"; then
        ip netns del "$ns" && echo "[teardown] Removed: $ns"
    fi
done

echo "[teardown] Done."
