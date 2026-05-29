.PHONY: help build build-release check test fmt lean-spec prehive run run-release

help:
	@echo "Common Peam commands:"
	@echo "  make build           Build the workspace"
	@echo "  make build-release   Build the peam binary in release mode"
	@echo "  make check           cargo check --lib"
	@echo "  make test            Run cargo test"
	@echo "  make fmt             Format the workspace"
	@echo "  make lean-spec       Run the leanSpec harness"
	@echo "  make prehive         Run the pre-Hive confidence suite"
	@echo "  make run             Run peam with CONFIG=... DATA_DIR=... and optional overrides"
	@echo "  make run-release     Run release peam with CONFIG=... DATA_DIR=... and optional overrides"
	@echo ""
	@echo "Run variables:"
	@echo "  CONFIG=/path/to/config.yaml"
	@echo "  DATA_DIR=/path/to/data"
	@echo "Optional:"
	@echo "  BOOTNODES=/path/to/nodes.yaml"
	@echo "  VALIDATORS=/path/to/validators.yaml"
	@echo "  VALIDATOR_KEYS=/path/to/hash-sig-keys"
	@echo "  NODE_KEY=/path/to/node.key"
	@echo "  NODE_ID=peam_0"
	@echo "  API_PORT=5052"
	@echo "  METRICS_PORT=5054"
	@echo "  CHECKPOINT_SYNC_URL=http://127.0.0.1:5052"
	@echo "  LISTEN=/ip4/0.0.0.0/udp/9000/quic-v1"
	@echo "  ATTESTATION_COMMITTEE_COUNT=1"
	@echo "  IS_AGGREGATOR=1"
	@echo "  VERBOSE=1"
	@echo "  NO_COLOR=1"

build:
	cargo build

build-release:
	cargo build --release -p peam --bin peam

check:
	cargo check --lib

test:
	cargo test

fmt:
	cargo fmt --all

lean-spec:
	./scripts/test_lean_spec.sh $(FIXTURES)

prehive:
	./scripts/test_pre_hive_confidence.sh $(FIXTURES)

run:
	@test -n "$(CONFIG)" || (echo "CONFIG=/path/to/config.yaml is required"; exit 1)
	@test -n "$(DATA_DIR)" || (echo "DATA_DIR=/path/to/data is required"; exit 1)
	@set -eu; \
	args="--run --config \"$(CONFIG)\" --data-dir \"$(DATA_DIR)\""; \
	if [ -n "$(BOOTNODES)" ]; then args="$$args --bootnodes \"$(BOOTNODES)\""; fi; \
	if [ -n "$(VALIDATORS)" ]; then args="$$args --validators \"$(VALIDATORS)\""; fi; \
	if [ -n "$(VALIDATOR_KEYS)" ]; then args="$$args --validator-keys \"$(VALIDATOR_KEYS)\""; fi; \
	if [ -n "$(NODE_KEY)" ]; then args="$$args --node-key \"$(NODE_KEY)\""; fi; \
	if [ -n "$(NODE_ID)" ]; then args="$$args --node-id \"$(NODE_ID)\""; fi; \
	if [ -n "$(API_PORT)" ]; then args="$$args --api-port \"$(API_PORT)\""; fi; \
	if [ -n "$(METRICS_PORT)" ]; then args="$$args --metrics-port \"$(METRICS_PORT)\""; fi; \
	if [ -n "$(CHECKPOINT_SYNC_URL)" ]; then args="$$args --checkpoint-sync-url \"$(CHECKPOINT_SYNC_URL)\""; fi; \
	if [ -n "$(LISTEN)" ]; then args="$$args --listen \"$(LISTEN)\""; fi; \
	if [ -n "$(ATTESTATION_COMMITTEE_COUNT)" ]; then args="$$args --attestation-committee-count \"$(ATTESTATION_COMMITTEE_COUNT)\""; fi; \
	if [ "$(IS_AGGREGATOR)" = "1" ]; then args="$$args --is-aggregator"; fi; \
	if [ "$(VERBOSE)" = "1" ]; then args="$$args --verbose"; fi; \
	if [ "$(NO_COLOR)" = "1" ]; then args="$$args --no-color"; fi; \
	eval cargo run -p peam --bin peam -- $$args

run-release:
	@test -n "$(CONFIG)" || (echo "CONFIG=/path/to/config.yaml is required"; exit 1)
	@test -n "$(DATA_DIR)" || (echo "DATA_DIR=/path/to/data is required"; exit 1)
	@set -eu; \
	args="--run --config \"$(CONFIG)\" --data-dir \"$(DATA_DIR)\""; \
	if [ -n "$(BOOTNODES)" ]; then args="$$args --bootnodes \"$(BOOTNODES)\""; fi; \
	if [ -n "$(VALIDATORS)" ]; then args="$$args --validators \"$(VALIDATORS)\""; fi; \
	if [ -n "$(VALIDATOR_KEYS)" ]; then args="$$args --validator-keys \"$(VALIDATOR_KEYS)\""; fi; \
	if [ -n "$(NODE_KEY)" ]; then args="$$args --node-key \"$(NODE_KEY)\""; fi; \
	if [ -n "$(NODE_ID)" ]; then args="$$args --node-id \"$(NODE_ID)\""; fi; \
	if [ -n "$(API_PORT)" ]; then args="$$args --api-port \"$(API_PORT)\""; fi; \
	if [ -n "$(METRICS_PORT)" ]; then args="$$args --metrics-port \"$(METRICS_PORT)\""; fi; \
	if [ -n "$(CHECKPOINT_SYNC_URL)" ]; then args="$$args --checkpoint-sync-url \"$(CHECKPOINT_SYNC_URL)\""; fi; \
	if [ -n "$(LISTEN)" ]; then args="$$args --listen \"$(LISTEN)\""; fi; \
	if [ -n "$(ATTESTATION_COMMITTEE_COUNT)" ]; then args="$$args --attestation-committee-count \"$(ATTESTATION_COMMITTEE_COUNT)\""; fi; \
	if [ "$(IS_AGGREGATOR)" = "1" ]; then args="$$args --is-aggregator"; fi; \
	if [ "$(VERBOSE)" = "1" ]; then args="$$args --verbose"; fi; \
	if [ "$(NO_COLOR)" = "1" ]; then args="$$args --no-color"; fi; \
	eval cargo run --release -p peam --bin peam -- $$args
