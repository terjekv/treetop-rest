#!/usr/bin/env bash

set -euo pipefail

if ! command -v k6 >/dev/null 2>&1; then
    echo "k6 is required; this scenario is verified with k6 2.2.0" >&2
    exit 1
fi

output=${TREETOP_K6_OUTPUT:-performance-results/k6.json}
output_parent=${output%/*}
if [[ ${output_parent} != "${output}" ]]; then
    mkdir -p "${output_parent}"
fi

k6_version=$(k6 version | awk '{print $2}')
export TREETOP_K6_VERSION=${TREETOP_K6_VERSION:-${k6_version}}
export TREETOP_K6_LOGICAL_CPUS=${TREETOP_K6_LOGICAL_CPUS:-$(nproc)}
export TREETOP_K6_OS=${TREETOP_K6_OS:-$(uname -s)}
export TREETOP_K6_ARCH=${TREETOP_K6_ARCH:-$(uname -m)}
export TREETOP_K6_KERNEL=${TREETOP_K6_KERNEL:-$(uname -r)}
export TREETOP_K6_OUTPUT=${output}

provenance_variables=(
    TREETOP_K6_REST_VERSION
    TREETOP_K6_REST_SHA
    TREETOP_K6_CORE_VERSION
    TREETOP_K6_CORE_SHA
    TREETOP_K6_CEDAR_VERSION
)
missing_provenance=()
for variable in "${provenance_variables[@]}"; do
    if [[ -z ${!variable:-} ]]; then
        missing_provenance+=("${variable}")
    fi
done
if (( ${#missing_provenance[@]} > 0 )); then
    echo "Warning: result is not publishable without ${missing_provenance[*]}" >&2
fi

if [[ -z ${TREETOP_K6_CPU_MODEL:-} && -r /proc/cpuinfo ]]; then
    TREETOP_K6_CPU_MODEL=$(awk -F ': ' '/^model name/ { print $2; exit }' /proc/cpuinfo)
    export TREETOP_K6_CPU_MODEL
fi

governor_path=/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
if [[ -z ${TREETOP_K6_CPU_GOVERNOR:-} && -r ${governor_path} ]]; then
    TREETOP_K6_CPU_GOVERNOR=$(<"${governor_path}")
    export TREETOP_K6_CPU_GOVERNOR
fi

k6_command=(
    k6 run
    --no-usage-report
    --summary-time-unit ms
    --summary-trend-stats "avg,min,med,p(90),p(95),p(99),max"
    tests/load/treetop.js
)

if [[ -n ${TREETOP_K6_CLIENT_CPUS:-} ]]; then
    if ! command -v taskset >/dev/null 2>&1; then
        echo "taskset is required when TREETOP_K6_CLIENT_CPUS is set" >&2
        exit 1
    fi
    taskset -c "${TREETOP_K6_CLIENT_CPUS}" "${k6_command[@]}"
else
    "${k6_command[@]}"
fi
