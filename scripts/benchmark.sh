#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

COMPOSE_FILE="$ROOT/compose.benchmark.yml"
RUN_ROOT="$ROOT/.benchmark-runs"
mkdir -p "$RUN_ROOT"

command_name=${1:-help}
shift || true
project=${BENCHMARK_PROJECT:-"hypersoc-benchmark-$(date -u +%Y%m%d%H%M%S)-$$"}
case "$project" in
  hypersoc-benchmark-*) ;;
  *) printf 'BENCHMARK_PROJECT must begin with hypersoc-benchmark-: %s\n' "$project" >&2; exit 2 ;;
esac

compose=(docker compose -p "$project" -f "$COMPOSE_FILE")
started=false
cleanup() {
  if [[ "$started" == true && "${BENCHMARK_KEEP_STACK:-0}" != 1 ]]; then
    "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

start_stack() {
  "${compose[@]}" up -d --build postgres migrate backend
  started=true
  local container status
  container=$("${compose[@]}" ps -q backend)
  for _ in $(seq 1 60); do
    status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container")
    [[ "$status" == healthy ]] && return 0
    [[ "$status" == unhealthy || "$status" == exited || "$status" == dead ]] && break
    sleep 1
  done
  "${compose[@]}" logs --no-color migrate backend >&2
  return 1
}

run_backend() {
  "${compose[@]}" exec -T -w /workspace backend python "$@"
}

new_output() {
  local prefix=$1 path
  path="/results/${prefix}-$(date -u +%Y%m%dT%H%M%SZ)-$$.json"
  [[ ! -e "$ROOT/.benchmark-runs/${path#/results/}" ]] || { printf 'Refusing to overwrite %s\n' "$path" >&2; exit 2; }
  printf '%s\n' "$path"
}

case "$command_name" in
  tests)
    docker build --target test -t hypersoc-backend-test -f backend/Dockerfile .
    docker run --rm --network none -e APP_SECRET_KEY=test-ingest-secret-value -e SECURITY_RATE_LIMIT_PER_MINUTE=100000 \
      -v "$ROOT/backend:/app:ro" -w /app hypersoc-backend-test python -m pytest tests/ -q -p no:cacheprovider
    docker run --rm --network none -e APP_SECRET_KEY=test-ingest-secret-value \
      -v "$ROOT:/workspace:ro" -w /workspace/benchmarks hypersoc-backend-test \
      python -m unittest discover -s . -p 'test_*.py' -v
    ;;
  pilot-smoke)
    output=${1:-$(new_output pilot-smoke)}
    [[ "$output" == /results/* ]] || { printf 'Output must be under /results\n' >&2; exit 2; }
    start_stack
    run_backend benchmarks/pilot_smoke.py --base-url http://127.0.0.1:8000 --output "$output"
    run_backend benchmarks/validate_result.py pilot "$output"
    printf 'Result: %s\n' "$ROOT/.benchmark-runs/${output#/results/}"
    ;;
  workload)
    output=${1:-$(new_output full-workload)}
    [[ "$output" == /results/* ]] || { printf 'Output must be under /results\n' >&2; exit 2; }
    start_stack
    run_backend benchmarks/batch_replay.py --base-url http://127.0.0.1:8000 --isolated-db --output "$output"
    run_backend benchmarks/validate_result.py workload "$output"
    printf 'Result: %s\n' "$ROOT/.benchmark-runs/${output#/results/}"
    ;;
  workload-triage|workload-jev)
    if [[ "$command_name" == workload-jev ]]; then
      compose=(docker compose -p "$project" -f "$COMPOSE_FILE" -f "$ROOT/compose.benchmark.openrouter.yml")
      output=${1:-$(new_output full-workload-jev)}
    else
      output=${1:-$(new_output full-workload-triage)}
    fi
    [[ "$output" == /results/* ]] || { printf 'Output must be under /results\n' >&2; exit 2; }
    start_stack
    run_backend benchmarks/batch_replay.py --base-url http://127.0.0.1:8000 --isolated-db --triage --output "$output"
    run_backend benchmarks/validate_result.py workload "$output"
    printf 'Result: %s\n' "$ROOT/.benchmark-runs/${output#/results/}"
    ;;
  workload-worker)
    # Production path: signed ingestion queues one job per alert and real workers drain them.
    workers=${BENCHMARK_WORKERS:-1}
    [[ "$workers" =~ ^[1-9][0-9]*$ ]] || { printf 'BENCHMARK_WORKERS must be a positive integer
' >&2; exit 2; }
    output=${1:-$(new_output worker-workload)}
    [[ "$output" == /results/* ]] || { printf 'Output must be under /results
' >&2; exit 2; }
    export BENCHMARK_AUTOMATION=true
    compose=(docker compose -p "$project" -f "$COMPOSE_FILE" --profile worker)
    start_stack
    "${compose[@]}" up -d --scale worker="$workers" worker
    run_backend benchmarks/worker_replay.py --base-url http://127.0.0.1:8000 --isolated-db       --workers "$workers" --label "${BENCHMARK_LABEL:-}" --timeout "${BENCHMARK_TIMEOUT:-3600}" --output "$output"
    printf 'Result: %s
' "$ROOT/.benchmark-runs/${output#/results/}"
    ;;
  verify-source)
    docker build --target test -t hypersoc-backend-test -f backend/Dockerfile .
    docker run --rm -v "$ROOT:/workspace:ro" -w /workspace hypersoc-backend-test \
      python benchmarks/verify_observed_source.py
    ;;
  prepare)
    output=${1:-"/results/pilot-$(date -u +%Y%m%dT%H%M%SZ)-$$/packets"}
    docker build --target test -t hypersoc-backend-test -f backend/Dockerfile .
    docker run --rm -v "$ROOT:/workspace:ro" -v "$RUN_ROOT:/results" -w /workspace \
      hypersoc-backend-test python benchmarks/soc_benchmark.py prepare --output "$output"
    ;;
  clean)
    while IFS= read -r name; do
      [[ -n "$name" ]] && docker compose -p "$name" -f "$COMPOSE_FILE" down --volumes --remove-orphans
    done < <(
      docker ps -a --filter label=com.docker.compose.project \
        --format '{{.Label "com.docker.compose.project"}}' | sort -u | grep '^hypersoc-benchmark-' || true
    )
    ;;
  help|*)
    cat <<'USAGE'
Usage: scripts/benchmark.sh COMMAND [OUTPUT]
  tests          Run backend and benchmark unit tests in the test image
  pilot-smoke    Run C01 through a disposable offline stack
  workload       Run the pinned 738-alert workload through a disposable stack
  workload-triage Run workload with offline incident triage
  workload-jev   Run workload with OpenRouter Jev triage (external requests/cost)
  workload-worker Run the 738-alert workload through ingestion and BENCHMARK_WORKERS workers
  verify-source  Verify observed cases against the pinned public source
  prepare        Create blinded pilot packets under .benchmark-runs
  clean          Remove leftover hypersoc-benchmark-* Compose projects
USAGE
    [[ "$command_name" == help ]] || exit 2
    ;;
esac
