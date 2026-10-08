.PHONY: build test benchmark-test benchmark-smoke benchmark-workload benchmark-triage benchmark-jev benchmark-worker benchmark-verify benchmark-prepare benchmark-clean compose-up compose-down

build:
	docker compose build backend

test:
	./scripts/benchmark.sh tests

benchmark-test:
	./scripts/benchmark.sh tests

benchmark-smoke:
	./scripts/benchmark.sh pilot-smoke

benchmark-workload:
	./scripts/benchmark.sh workload

benchmark-triage:
	./scripts/benchmark.sh workload-triage

benchmark-jev:
	./scripts/benchmark.sh workload-jev

benchmark-worker:
	./scripts/benchmark.sh workload-worker

benchmark-verify:
	./scripts/benchmark.sh verify-source

benchmark-prepare:
	./scripts/benchmark.sh prepare

benchmark-clean:
	./scripts/benchmark.sh clean

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down
