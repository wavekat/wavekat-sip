.PHONY: help check test fmt lint doc ci e2e-asterisk asterisk-up asterisk-down

help:
	@echo "Available targets:"
	@echo "  check     Check workspace compiles"
	@echo "  test      Run all tests"
	@echo "  fmt       Format code"
	@echo "  lint      Run clippy with warnings as errors"
	@echo "  doc       Build and open docs in browser"
	@echo "  ci        Run all CI checks locally (fmt, clippy, test, doc)"
	@echo "  e2e-asterisk  Run the end-to-end tests against Asterisk in Docker"
	@echo "  asterisk-up   Start the Asterisk test server (left running)"
	@echo "  asterisk-down Stop it"

check:
	cargo check --workspace

test:
	cargo test --workspace

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-features -- -D warnings
	cargo clippy --workspace -- -D warnings

doc:
	cargo doc --no-deps -p wavekat-sip --all-features --open

ci:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-features -- -D warnings
	cargo clippy --workspace -- -D warnings
	cargo test --workspace --all-features
	cargo test --workspace
	cargo doc --no-deps -p wavekat-sip --all-features

# ── End-to-end tests against a real Asterisk (tests/asterisk.rs) ──────────
# Docker is the only requirement. The image is pinned, so a new Asterisk
# release can't change what these tests mean without a commit here.
ASTERISK_IMAGE ?= andrius/asterisk:22.8-cert4_debian-trixie
ASTERISK_CONTAINER ?= wavekat-sip-asterisk
ASTERISK_PORT ?= 5060

asterisk-up:
	@docker rm -f $(ASTERISK_CONTAINER) >/dev/null 2>&1 || true
	docker run -d --name $(ASTERISK_CONTAINER) \
		-p $(ASTERISK_PORT):5060/udp -p $(ASTERISK_PORT):5060/tcp \
		-v "$(CURDIR)/e2e/asterisk/pjsip.conf:/etc/asterisk/pjsip.conf:ro" \
		-v "$(CURDIR)/e2e/asterisk/extensions.conf:/etc/asterisk/extensions.conf:ro" \
		-v "$(CURDIR)/e2e/asterisk/modules.conf:/etc/asterisk/modules.conf:ro" \
		$(ASTERISK_IMAGE) >/dev/null
	@for i in $$(seq 1 60); do \
		docker exec $(ASTERISK_CONTAINER) asterisk -rx "core waitfullybooted" >/dev/null 2>&1 && exit 0; \
		sleep 1; \
	done; echo "Asterisk did not boot within 60 s"; docker logs --tail 50 $(ASTERISK_CONTAINER); exit 1

asterisk-down:
	@docker rm -f $(ASTERISK_CONTAINER) >/dev/null 2>&1 || true

# One test at a time: they share two accounts, and one restarts the server.
e2e-asterisk: asterisk-up
	WAVEKAT_E2E_SIP_PORT=$(ASTERISK_PORT) WAVEKAT_E2E_ASTERISK_CONTAINER=$(ASTERISK_CONTAINER) \
		cargo test -p wavekat-sip --all-features --test asterisk -- --ignored --test-threads=1; \
		status=$$?; \
		if [ $$status -ne 0 ]; then echo "── Asterisk log ──"; docker logs --tail 200 $(ASTERISK_CONTAINER) 2>&1; fi; \
		$(MAKE) --no-print-directory asterisk-down; exit $$status
