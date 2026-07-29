.PHONY: demo down reset-demo build lint test check policy-test

COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")
PROJECT := secure-it-demo

demo: build test policy-test
	$(COMPOSE) -p $(PROJECT) up -d postgres opa
	@echo "Demo lista. Para stdio de desarrollo ejecute 'SECUREIT_MODE=demo npm run dev:mcp:stdio'."

down:
	$(COMPOSE) -p $(PROJECT) down

reset-demo:
	@test "$(PROJECT)" = "secure-it-demo"
	$(COMPOSE) -p $(PROJECT) down --volumes

build:
	npm ci
	npm run build

lint:
	npm run lint

test:
	npm test

check:
	npm run check

policy-test:
	docker run --rm -v "$$(pwd)/deploy/opa:/policies:ro" openpolicyagent/opa:1.4.2-static test /policies
