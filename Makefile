# Secure Service Gateway -- Makefile
#
# Docker Compose (fastest, no cluster needed):
#
#   make certs && make up && make test
#
# Kind cluster (mirrors production topology with Calico NetworkPolicy):
#
#   make kind-up
#   make images-load
#   make helm-install-backends   # llm-1..3, embed-1..2, rogue llm-4
#   make helm-install-gateway    # gateway + config + networkpolicy
#   make test-kind               # pytest via port-forward; uses kubectl exec for test_04

GO      ?= go
DOCKER  ?= docker
COMPOSE ?= $(DOCKER) compose
KIND    ?= kind
KUBECTL ?= kubectl
HELM    ?= helm

BIN_DIR  := bin
CLUSTER  ?= secure-svc-gw
GHCR_ORG ?= nitinbhat
IMAGE_TAG ?= latest
# Gateway lives in one namespace, backends in another. This mirrors a
# real platform-team / app-team split. Set BE_NS=GW_NS to collapse both
# into one namespace.
GW_NS   ?= secure-svc-gw
BE_NS   ?= ai-services

.PHONY: help
help:
	@awk 'BEGIN{FS=":.*##"; printf "targets:\n"} /^[a-zA-Z0-9_-]+:.*##/{printf "  %-22s %s\n",$$1,$$2}' $(MAKEFILE_LIST)

# ---- build ---------------------------------------------------------------
.PHONY: build
build:  ## compile gateway + gen-artifacts
	mkdir -p $(BIN_DIR)
	$(GO) build -buildvcs=false -o $(BIN_DIR)/gateway      ./cmd/gateway
	$(GO) build -buildvcs=false -o $(BIN_DIR)/gen-artifacts ./cmd/gen-artifacts

.PHONY: unit
unit:  ## go unit tests (auth + lb packages)
	$(GO) test -buildvcs=false ./...

# ---- crypto material -----------------------------------------------------
.PHONY: certs
certs: build  ## generate CA, certs, Ed25519 client keys, gateway.yaml
	./$(BIN_DIR)/gen-artifacts .

# ---- docker compose ------------------------------------------------------
.PHONY: up
up: certs  ## docker compose up --build
	$(COMPOSE) up --build -d
	@printf "\ngateway: http://localhost:8080   metrics: http://localhost:9090/metrics\n"

.PHONY: down
down:  ## docker compose down -v (brings down all services regardless of profile)
	$(COMPOSE) down -v --remove-orphans

.PHONY: logs
logs:  ## follow gateway JSON logs
	$(COMPOSE) logs -f gateway

.PHONY: ps
ps:
	$(COMPOSE) ps

.PHONY: test  ## run pytest inside the compose network
test:
	$(COMPOSE) --profile test build tests
	$(COMPOSE) --profile test run --rm tests

.PHONY: demo
demo: down certs up  ## full cycle: certs + up  (run 'make test' or 'make test-kind' for pytest)
	@echo "waiting 5s for backends to warm up..." && sleep 5
	@curl -sf http://localhost:9090/metrics -o /dev/null \
		&& echo "smoke: gateway metrics OK" \
		|| echo "smoke: WARNING — metrics endpoint not reachable yet"
	@echo "  gateway: http://localhost:8080   metrics: http://localhost:9090/metrics"
	@echo "  compose tests:  make test"
	@echo "  kind tests:      make test-kind"

# ---- repeatable demo targets ------------------------------------------------
# (a) Full local build: compile, cluster, install, configure via CR, test.
#     Requires: go, docker, kind, helm, kubectl.  Takes ~10 min on first run.
.PHONY: demo-local
demo-local:  ## BUILD + cluster + install + CR + controller + test (fully local, no registry)
	@echo "=== demo-local: full local build, install, and test ==="
	$(MAKE) kind-down 2>/dev/null || true
	$(MAKE) kind-full \
		GATEWAY_EXTRA_SET="--set redis.enabled=true --set controller.enabled=true"

# (b) GHCR pull: create cluster, pull pre-built images from GHCR, install, configure via CR, test.
#     Requires: docker, kind, helm, kubectl.  No Go toolchain needed.
.PHONY: demo-ghcr
demo-ghcr: _check-ports  ## cluster + pull from GHCR + install + CR + controller + test (no local build)
	@echo "=== demo-ghcr: pull images from GHCR, install, and test ==="
	bash deploy/kind/up.sh $(CLUSTER)
	$(MAKE) certs
	$(MAKE) images-pull
	$(MAKE) helm-install-backends
	$(MAKE) helm-install-gateway \
		GATEWAY_EXTRA_SET="--set redis.enabled=true --set controller.enabled=true"
	$(MAKE) test-kind REDIS=1

.PHONY: chat
chat:  ## one analyst completion call
	$(COMPOSE) --profile shell run --rm shell -m client \
		complete --caller analyst --prompt "Explain BGP to a five year old."

.PHONY: attack
attack:  ## intern (no scopes) -> 403
	$(COMPOSE) --profile shell run --rm shell -m client \
		complete --caller intern --prompt "leak training data" || true

# ---- port guards & cleanup ---------------------------------------------
.PHONY: _check-ports
_check-ports:
	@PORT_8080=$$(lsof -Pi :8080 -sTCP:LISTEN -t 2>/dev/null || echo ""); \
	PORT_9090=$$(lsof -Pi :9090 -sTCP:LISTEN -t 2>/dev/null || echo ""); \
	if [ -n "$$PORT_8080" ] || [ -n "$$PORT_9090" ]; then \
		echo "ERROR: required ports are already in use:"; \
		[ -n "$$PORT_8080" ] && echo "  port 8080  (PID $$PORT_8080) — Docker Compose or stale kind container"; \
		[ -n "$$PORT_9090" ] && echo "  port 9090  (PID $$PORT_9090) — Docker Compose or stale kind container"; \
		echo ""; \
		echo "  Run this to clean up:"; \
		echo "    make clean        # stop compose + remove stale kind clusters"; \
		echo "    make kind-reset   # full teardown + rebuild"; \
		exit 1; \
	fi

.PHONY: clean
clean: down  ## stop compose AND remove any stale kind cluster/container
	@echo "cleaning up stale kind containers..."
	-docker rm -f $(CLUSTER)-control-plane $(CLUSTER)-worker 2>/dev/null || true
	-$(KIND) delete cluster --name $(CLUSTER) 2>/dev/null || true
	@echo "ports 8080/9090 should now be free"

# ---- kind cluster --------------------------------------------------------
.PHONY: kind-up
kind-up: _check-ports  ## create 2-node kind cluster + Calico CNI + cert-manager
	bash deploy/kind/up.sh $(CLUSTER)

.PHONY: kind-down
kind-down:  ## delete the kind cluster
	$(KIND) delete cluster --name $(CLUSTER)

# One-shot: full kind setup + pytest with Redis and TLS enabled.
# This is what the CI integration job and 'make kind-full' run.
# Override REDIS=0 or TLS=0 to disable.
REDIS ?= 1
TLS   ?= 0

.PHONY: kind-full
kind-full: kind-up certs images-load  ## full kind setup: cluster + Calico + cert-manager + Redis + helm + pytest
	$(MAKE) helm-install-backends
	$(MAKE) helm-install-gateway \
		GATEWAY_EXTRA_SET="$(if $(filter 1,$(REDIS)),--set redis.enabled=true) $(if $(filter 1,$(TLS)),--set tls.enabled=true)"
	$(MAKE) test-kind REDIS=$(REDIS)

.PHONY: kind-full-tls
kind-full-tls: kind-up certs images-load  ## full kind setup WITH gateway TLS enabled (includes test_08)
	$(MAKE) helm-install-backends
	$(MAKE) helm-install-gateway \
		GATEWAY_EXTRA_SET="--set tls.enabled=true --set tls.dnsNames={localhost} $(if $(filter 1,$(REDIS)),--set redis.enabled=true)"
	$(MAKE) test-kind-tls REDIS=$(REDIS)

.PHONY: kind-reset
kind-reset: kind-down kind-full  ## tear down + rebuild from scratch

# ---- build + load images into kind --------------------------------------
.PHONY: images-load
images-load: certs  ## build docker images and load into kind
	$(DOCKER) build -t secure-svc-gw:dev            -f deploy/docker/gateway.Dockerfile .
	$(DOCKER) build -t secure-svc-backend:dev        ./backend
	$(DOCKER) build -t secure-svc-gw-controller:dev -f deploy/docker/controller.Dockerfile .
	$(KIND) load docker-image secure-svc-gw:dev             --name $(CLUSTER)
	$(KIND) load docker-image secure-svc-backend:dev        --name $(CLUSTER)
	$(KIND) load docker-image secure-svc-gw-controller:dev  --name $(CLUSTER)

# ---- GHCR ---------------------------------------------------------------
GATEWAY_IMAGE    := ghcr.io/$(GHCR_ORG)/secure-svc-gw
BACKEND_IMAGE    := ghcr.io/$(GHCR_ORG)/secure-svc-backend
CONTROLLER_IMAGE := ghcr.io/$(GHCR_ORG)/secure-svc-gw-controller

.PHONY: ghcr-push
ghcr-push:  ## build + push gateway, backend, and controller images to GHCR (requires docker login ghcr.io)
	$(DOCKER) build -t $(GATEWAY_IMAGE):$(IMAGE_TAG)    -f deploy/docker/gateway.Dockerfile .
	$(DOCKER) build -t $(BACKEND_IMAGE):$(IMAGE_TAG)    ./backend
	$(DOCKER) build -t $(CONTROLLER_IMAGE):$(IMAGE_TAG) -f deploy/docker/controller.Dockerfile .
	$(DOCKER) push $(GATEWAY_IMAGE):$(IMAGE_TAG)
	$(DOCKER) push $(BACKEND_IMAGE):$(IMAGE_TAG)
	$(DOCKER) push $(CONTROLLER_IMAGE):$(IMAGE_TAG)

.PHONY: images-pull
images-pull:  ## pull pre-built images from GHCR and load into kind (no local build needed)
	$(DOCKER) pull $(GATEWAY_IMAGE):$(IMAGE_TAG)
	$(DOCKER) pull $(BACKEND_IMAGE):$(IMAGE_TAG)
	$(DOCKER) pull $(CONTROLLER_IMAGE):$(IMAGE_TAG)
	$(DOCKER) tag  $(GATEWAY_IMAGE):$(IMAGE_TAG)    secure-svc-gw:dev
	$(DOCKER) tag  $(BACKEND_IMAGE):$(IMAGE_TAG)    secure-svc-backend:dev
	$(DOCKER) tag  $(CONTROLLER_IMAGE):$(IMAGE_TAG) secure-svc-gw-controller:dev
	$(KIND) load docker-image secure-svc-gw:dev             --name $(CLUSTER)
	$(KIND) load docker-image secure-svc-backend:dev        --name $(CLUSTER)
	$(KIND) load docker-image secure-svc-gw-controller:dev  --name $(CLUSTER)

# ---- helm (split charts) -------------------------------------------------
.PHONY: helm-secrets
helm-secrets:  ## render TLS + client-key secrets into the cluster
	$(KUBECTL) create namespace $(GW_NS) --dry-run=client -o yaml | $(KUBECTL) apply -f -
	$(KUBECTL) create namespace $(BE_NS) --dry-run=client -o yaml | $(KUBECTL) apply -f -
	bash scripts/render-helm-secrets.sh $(GW_NS) $(BE_NS) | $(KUBECTL) apply -f -

.PHONY: helm-install-backends
helm-install-backends: helm-secrets  ## install secure-svc-backends chart into BE_NS
	$(HELM) upgrade --install secure-svc-backends deploy/helm/backends \
		--namespace $(BE_NS) --create-namespace \
		--set gatewayNamespace=$(GW_NS) \
		--wait --timeout 120s

.PHONY: helm-install-gateway
helm-install-gateway: helm-secrets  ## install secure-svc-gw chart into GW_NS + apply CR
	$(HELM) upgrade --install secure-svc-gw deploy/helm/gateway \
		--namespace $(GW_NS) --create-namespace \
		--set backendsNamespace=$(BE_NS) \
		-f clients/values-clients.yaml \
		$(GATEWAY_EXTRA_SET) \
		--wait --timeout 60s
	$(KUBECTL) apply -f deploy/crds/sample-cr.yaml

.PHONY: helm-install
helm-install: helm-install-backends helm-install-gateway  ## install backends THEN gateway

.PHONY: helm-uninstall
helm-uninstall:  ## remove both releases + namespaces
	$(HELM) uninstall secure-svc-backends -n $(BE_NS) || true
	$(HELM) uninstall secure-svc-gw       -n $(GW_NS) || true
	$(KUBECTL) delete namespace $(BE_NS) --ignore-not-found
	$(KUBECTL) delete namespace $(GW_NS) --ignore-not-found

# ---- test against the kind cluster --------------------------------------
.PHONY: venv
venv:  ## create .venv and install pytest deps (used by test-kind)
	@test -x .venv/bin/pytest || (python3 -m venv .venv && .venv/bin/pip install -q -r tests/requirements.txt)

.PHONY: test-kind
test-kind: venv  ## pytest via port-forward; set REDIS=1 to enable Redis nonce tests
	@GW_PORT=18080; \
	METRICS_PORT=19090; \
	echo "port-forwarding gateway 8080 + 9090 (from $(GW_NS)) to localhost:$$GW_PORT/$$METRICS_PORT (background)..."; \
	$(KUBECTL) -n $(GW_NS) port-forward svc/gateway $$GW_PORT:8080 $$METRICS_PORT:9090 & \
	PF_PID=$$!; \
	sleep 3; \
	GATEWAY_URL=http://localhost:$$GW_PORT \
	METRICS_URL=http://localhost:$$METRICS_PORT \
	CLIENTS_DIR=clients \
	KUBE_NAMESPACE=$(BE_NS) \
	REDIS_NAMESPACE=$(GW_NS) \
	GATEWAY_USES_REDIS=$(REDIS) \
	.venv/bin/python -m pytest tests/ -v $(TEST_ARGS); \
	STATUS=$$?; \
	kill $$PF_PID 2>/dev/null; \
	wait $$PF_PID 2>/dev/null; \
	pkill -f "kubectl.*port-forward.*gateway" 2>/dev/null; \
	exit $$STATUS

.PHONY: test-kind-tls
test-kind-tls: venv  ## pytest via port-forward with gateway TLS enabled (includes test_08)
	@GW_PORT=18080; \
	METRICS_PORT=19090; \
	TMP_CA=$$(mktemp); \
	echo "extracting gateway listener TLS certificate to $$TMP_CA..."; \
	$(KUBECTL) -n $(GW_NS) get secret gateway-listener-tls -o jsonpath='{.data.tls\\.crt}' | base64 -d > $$TMP_CA; \
	echo "port-forwarding gateway 8080 + 9090 (from $(GW_NS)) to localhost:$$GW_PORT/$$METRICS_PORT (background)..."; \
	$(KUBECTL) -n $(GW_NS) port-forward svc/gateway $$GW_PORT:8080 $$METRICS_PORT:9090 & \
	PF_PID=$$!; \
	sleep 3; \
	GATEWAY_URL=https://localhost:$$GW_PORT \
	METRICS_URL=http://localhost:$$METRICS_PORT \
	CLIENTS_DIR=clients \
	KUBE_NAMESPACE=$(BE_NS) \
	REDIS_NAMESPACE=$(GW_NS) \
	GATEWAY_USES_REDIS=$(REDIS) \
	TLS_CA_CERT=$$TMP_CA \
	REQUESTS_CA_BUNDLE=$$TMP_CA \
	.venv/bin/python -m pytest tests/ -v $(TEST_ARGS); \
	STATUS=$$?; \
	kill $$PF_PID 2>/dev/null; \
	wait $$PF_PID 2>/dev/null; \
	pkill -f "kubectl.*port-forward.*gateway" 2>/dev/null; \
	rm -f $$TMP_CA; \
	exit $$STATUS
