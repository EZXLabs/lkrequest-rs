#!/usr/bin/env bash
set -euo pipefail

rounds="${ROUNDS:-3}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
results_dir="${RESULTS_DIR:-${repo_root}/benchmark-results/h2-client}"
executable="${repo_root}/target/release/http-client-bench"
client_runtime_workers="${CLIENT_RUNTIME_WORKERS:-1}"
server_runtime_workers="${SERVER_RUNTIME_WORKERS:-2}"

mkdir -p "${results_dir}"
cd "${repo_root}"
cargo build --release -p http-client-bench
{
  printf 'timestamp=%s\n' "$(date --iso-8601=seconds)"
  printf 'uname=%s\n' "$(uname -a)"
  printf 'rustc=%s\n' "$(rustc --version)"
  printf 'cargo=%s\n' "$(cargo --version)"
  printf 'client_runtime_workers=%s\n' "${client_runtime_workers}"
  printf 'server_runtime_workers=%s\n' "${server_runtime_workers}"
  command -v lscpu >/dev/null && lscpu
} >"${results_dir}/environment.txt"

server_pid=""
cleanup() {
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

run_group() {
  local body_size="$1"
  shift
  local scenarios=("$@")
  "${executable}" serve --listen 127.0.0.1:18481 --body-size "${body_size}" \
    --runtime-workers "${server_runtime_workers}" >"${results_dir}/server-${body_size}.out.log" \
    2>"${results_dir}/server-${body_size}.err.log" &
  server_pid=$!

  for _ in $(seq 1 100); do
    if grep -q "benchmark server listening" "${results_dir}/server-${body_size}.out.log"; then
      break
    fi
    sleep 0.1
  done

  local round scenario requests concurrency client output
  for round in $(seq 1 "${rounds}"); do
    if (( round % 2 == 1 )); then
      clients=(lkrequest hyper reqwest)
    else
      clients=(reqwest hyper lkrequest)
    fi
    set -- "${scenarios[@]}"
    while (($#)); do
      scenario="$1"
      requests="$2"
      concurrency="$3"
      shift 3
      for client in "${clients[@]}"; do
        output="${results_dir}/${scenario}-round${round}-${client}.json"
        "${executable}" run --client "${client}" \
          --url http://127.0.0.1:18481/ \
          --requests "${requests}" \
          --concurrency "${concurrency}" \
          --warmup-requests 200 \
          --expected-bytes "${body_size}" \
          --runtime-workers "${client_runtime_workers}" \
          --output "${output}"
      done
    done
  done

  cleanup
  server_pid=""
}

run_group 1024 \
  sequential-reuse 20000 1 \
  multiplex-c8 30000 8 \
  multiplex-c32 50000 32 \
  multiplex-c128 50000 128

run_group 1048576 download-1m-c32 1000 32

python3 "${repo_root}/tools/http-client-bench/scripts/summarize.py" "${results_dir}"
