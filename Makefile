.PHONY: setup up down baseline inject-nat-failure inject-vpn-failure inject-bgp-failure \
        inject-mtu-blackhole inject-loss collect analyze test clean help

PYTHON := python3
LAB_SCRIPTS := lab/scripts
ANALYZER := analyzer
EXPERIMENTS := experiments

help:
	@echo "SATCOM Enterprise WAN - Available Commands"
	@echo "=========================================="
	@echo "  make setup              Install dependencies and configure environment"
	@echo "  make up                 Start telemetry stack (Prometheus + Grafana + API)"
	@echo "  make down               Stop telemetry stack"
	@echo "  make baseline           Run baseline connectivity test"
	@echo "  make inject-nat-failure Inject NAT misconfiguration failure"
	@echo "  make inject-vpn-failure Inject VPN handshake failure"
	@echo "  make inject-bgp-failure Inject BGP session failure (ASN mismatch)"
	@echo "  make inject-mtu-blackhole Inject MTU black hole"
	@echo "  make inject-loss        Inject 5%% packet loss via tc netem"
	@echo "  make collect            Collect diagnostics (routes, BGP, VPN, pcaps)"
	@echo "  make analyze            Run root cause analyzer on latest diagnostics"
	@echo "  make test               Run test suite"
	@echo "  make clean              Tear down lab and clean captures"

setup:
	@echo "[setup] Installing Python dependencies..."
	$(PYTHON) -m pip install -r requirements.txt
	@echo "[setup] Checking for required system tools..."
	@which ip || (echo "ERROR: 'ip' command not found (iproute2 required)" && exit 1)
	@which tcpdump || echo "WARNING: tcpdump not found - packet capture will be skipped"
	@which iperf3 || echo "WARNING: iperf3 not found - throughput tests will be skipped"
	@echo "[setup] Creating capture directories..."
	mkdir -p captures/{baseline,nat_failure,vpn_failure,bgp_failure,mtu_blackhole,packet_loss,high_latency,dns_failure,failover}
	@echo "[setup] Done."

up:
	@echo "[up] Starting telemetry stack..."
	docker compose up -d
	@echo "[up] Telemetry API: http://localhost:8000"
	@echo "[up] Prometheus:    http://localhost:9090"
	@echo "[up] Grafana:       http://localhost:3000 (admin / satcom123)"

down:
	@echo "[down] Stopping telemetry stack..."
	docker compose down

lab-up:
	@echo "[lab] Setting up network namespaces..."
	sudo bash $(LAB_SCRIPTS)/setup_lab.sh

lab-down:
	@echo "[lab] Tearing down network namespaces..."
	sudo bash $(LAB_SCRIPTS)/teardown_lab.sh

baseline:
	@echo "[baseline] Running baseline connectivity test..."
	sudo bash $(LAB_SCRIPTS)/run_baseline_test.sh 2>&1 | tee experiments/baseline/results.txt

inject-nat-failure:
	@echo "[inject] Injecting NAT misconfiguration..."
	sudo bash $(LAB_SCRIPTS)/inject_failure.sh nat_failure
	$(PYTHON) $(ANALYZER)/root_cause_analyzer.py --input experiments/nat_failure/diagnostics.json

inject-vpn-failure:
	@echo "[inject] Injecting VPN handshake failure..."
	sudo bash $(LAB_SCRIPTS)/inject_failure.sh vpn_failure
	$(PYTHON) $(ANALYZER)/root_cause_analyzer.py --input experiments/vpn_failure/diagnostics.json

inject-bgp-failure:
	@echo "[inject] Injecting BGP ASN mismatch..."
	sudo bash $(LAB_SCRIPTS)/inject_failure.sh bgp_failure
	$(PYTHON) $(ANALYZER)/root_cause_analyzer.py --input experiments/bgp_failure/diagnostics.json

inject-mtu-blackhole:
	@echo "[inject] Injecting MTU black hole..."
	sudo bash $(LAB_SCRIPTS)/inject_failure.sh mtu_blackhole
	$(PYTHON) $(ANALYZER)/root_cause_analyzer.py --input experiments/mtu_blackhole/diagnostics.json

inject-loss:
	@echo "[inject] Injecting 5%% packet loss..."
	sudo bash $(LAB_SCRIPTS)/inject_failure.sh packet_loss
	$(PYTHON) $(ANALYZER)/root_cause_analyzer.py --input experiments/packet_loss/diagnostics.json

collect:
	@echo "[collect] Collecting diagnostics..."
	sudo bash $(LAB_SCRIPTS)/collect_diagnostics.sh

analyze:
	@echo "[analyze] Running root cause analyzer..."
	@LATEST=$$(ls -t experiments/*/diagnostics.json 2>/dev/null | head -1); \
	if [ -z "$$LATEST" ]; then \
		echo "No diagnostics found. Run 'make collect' first."; exit 1; \
	fi; \
	echo "Analyzing: $$LATEST"; \
	$(PYTHON) $(ANALYZER)/root_cause_analyzer.py --input "$$LATEST"

test:
	@echo "[test] Running test suite..."
	$(PYTHON) -m pytest tests/ -v

clean:
	@echo "[clean] Tearing down lab..."
	-sudo bash $(LAB_SCRIPTS)/teardown_lab.sh 2>/dev/null
	@echo "[clean] Removing captures..."
	rm -rf captures/*/
	@echo "[clean] Removing experiment outputs..."
	find experiments/ -name "*.json" -o -name "*.txt" -o -name "*.pcap" | xargs rm -f 2>/dev/null || true
	@echo "[clean] Done."
