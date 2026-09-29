#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -uC

if [[ $# -lt 1 || $# -gt 2 || ( $# -eq 2 && $2 != --quiet ) ]]; then
    printf 'Usage: %s <ctest-log-path> [--quiet]\n' "$0" >&2
    exit 2
fi

log=$1
ctest_output=/dev/stdout
if [[ ${2:-} == --quiet ]]; then
    ctest_output=/dev/null
fi
metrics="${log}.resources"
samples="${log}.memory-samples"
if ! { exec 3> "$metrics"; }; then
    printf 'Cannot create resource log: %s\n' "$metrics" >&2
    exit 1
fi
if ! { exec 4> "$log"; }; then
    printf 'Cannot create test log: %s\n' "$log" >&2
    exit 1
fi

record() {
    printf '%s\n' "$*" >&3 || exit 1
    printf '%s\n' "$*" || exit 1
}

counter() {
    awk -v key="$2" '$1 == key { print $2; found = 1; exit } END { if (!found) exit 1 }' "$1"
}

memory_file=
cpu_file=
events_file=
if [[ -r /sys/fs/cgroup/memory.current ]]; then
    memory_file=/sys/fs/cgroup/memory.current
    cpu_file=/sys/fs/cgroup/cpu.stat
    events_file=/sys/fs/cgroup/memory.events
    record "cgroup=v2"
    if [[ -r /sys/fs/cgroup/memory.max ]]; then
        record "memory_limit_bytes=$(< /sys/fs/cgroup/memory.max)"
    else
        record "memory_limit_bytes=unavailable"
    fi
    if [[ -r /sys/fs/cgroup/cpu.max ]]; then
        record "cpu_quota_period=$(< /sys/fs/cgroup/cpu.max)"
    else
        record "cpu_quota_period=unavailable"
    fi
elif [[ -r /sys/fs/cgroup/memory/memory.usage_in_bytes ]]; then
    memory_file=/sys/fs/cgroup/memory/memory.usage_in_bytes
    if [[ -r /sys/fs/cgroup/memory/memory.oom_control ]]; then
        events_file=/sys/fs/cgroup/memory/memory.oom_control
    fi
    cpu_dir=/sys/fs/cgroup/cpu
    cpu_file=/sys/fs/cgroup/cpuacct/cpuacct.usage
    if [[ -r /sys/fs/cgroup/cpu,cpuacct/cpuacct.usage ]]; then
        cpu_dir=/sys/fs/cgroup/cpu,cpuacct
        cpu_file="${cpu_dir}/cpuacct.usage"
    fi
    record "cgroup=v1"
    if [[ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]]; then
        record "memory_limit_bytes=$(< /sys/fs/cgroup/memory/memory.limit_in_bytes)"
    else
        record "memory_limit_bytes=unavailable"
    fi
    if [[ -r "${cpu_dir}/cpu.cfs_quota_us" && -r "${cpu_dir}/cpu.cfs_period_us" ]]; then
        record "cpu_quota_period=$(< "${cpu_dir}/cpu.cfs_quota_us") $(< "${cpu_dir}/cpu.cfs_period_us")"
    else
        record "cpu_quota_period=unavailable"
    fi
else
    record "cgroup=unavailable"
    record "memory_limit_bytes=unavailable"
    record "cpu_quota_period=unavailable"
fi

if available_cpus=$(nproc); then
    record "available_cpus=$available_cpus"
else
    record "available_cpus=unavailable"
fi
record "ctest_parallel_jobs=8"

cpu_before=
if [[ -r "$cpu_file" ]]; then
    if [[ "$cpu_file" == */cpu.stat ]]; then
        cpu_before=$(counter "$cpu_file" usage_usec) || cpu_before=
    else
        cpu_before=$(< "$cpu_file")
    fi
fi
oom_before=
if [[ -r "$events_file" ]]; then
    oom_before=$(counter "$events_file" oom_kill) || oom_before=
fi
if [[ -r "$memory_file" ]]; then
    memory_before=$(< "$memory_file")
    record "memory_at_ctest_start_bytes=$memory_before"
else
    record "memory_at_ctest_start_bytes=unavailable"
fi

sampler_pid=
sampler_status=0
if [[ -n "$memory_file" ]]; then
    if ! { exec 5> "$samples"; }; then
        record "memory_sampling_status=failed (cannot create $samples)"
        exit 1
    fi
    (
        termination_requested=false
        trap 'termination_requested=true' TERM
        while :; do
            if [[ "$termination_requested" == true ]]; then
                exit 0
            fi
            if ! IFS= read -r memory < "$memory_file" || [[ ! "$memory" =~ ^[0-9]+$ ]]; then
                printf 'Cannot read cgroup memory usage\n' >&2
                exit 1
            fi
            if ! timestamp=$(date +%s%3N); then
                printf 'Cannot timestamp cgroup memory sample\n' >&2
                exit 1
            fi
            if ! printf '%s,%s\n' "$timestamp" "$memory" >&5; then
                printf 'Cannot write cgroup memory sample\n' >&2
                exit 1
            fi
            if [[ "$termination_requested" == true ]]; then
                exit 0
            fi
            if ! sleep 0.2; then
                if [[ "$termination_requested" != true ]]; then
                    printf 'Cannot wait between cgroup memory samples\n' >&2
                    exit 1
                fi
            fi
        done
    ) &
    sampler_pid=$!
else
    record "sampled_peak_memory_bytes=unavailable (cgroup memory counter unavailable)"
fi

stop_sampler() {
    if [[ -n "$sampler_pid" ]]; then
        kill "$sampler_pid" 2>/dev/null || true
        if wait "$sampler_pid"; then
            sampler_status=0
        else
            sampler_status=$?
        fi
        sampler_pid=
    fi
}
trap stop_sampler EXIT

start_ms=$(date +%s%3N)
ctest --verbose --parallel 8 2>&1 | tee /dev/fd/4 > "$ctest_output"
statuses=("${PIPESTATUS[@]}")
end_ms=$(date +%s%3N)
stop_sampler

sampling_failed=0
if [[ -n "$memory_file" ]]; then
    if [[ $sampler_status -eq 0 ]] && peak=$(awk -F, 'NF != 2 || $2 !~ /^[0-9]+$/ { bad = 1 } $2 > peak { peak = $2 }
        END { if (NR == 0 || bad) exit 1; printf "%.0f", peak }' "$samples"); then
        record "memory_sampling_status=complete"
        record "sampled_peak_memory_bytes=$peak"
        record "memory_samples_file=$samples"
    else
        sampling_failed=1
        record "memory_sampling_status=failed (sampler exit code $sampler_status or invalid samples)"
        record "sampled_peak_memory_bytes=unavailable (sampling failed)"
    fi
    if [[ -r "$memory_file" ]]; then
        record "memory_at_ctest_end_bytes=$(< "$memory_file")"
    else
        record "memory_at_ctest_end_bytes=unavailable"
    fi
else
    record "memory_at_ctest_end_bytes=unavailable"
fi
record "ctest_wall_ms=$((end_ms - start_ms))"

if [[ -n "$cpu_before" && -r "$cpu_file" ]]; then
    if [[ "$cpu_file" == */cpu.stat ]]; then
        cpu_after=$(counter "$cpu_file" usage_usec) || cpu_after=
        cpu_before_us=$cpu_before
    else
        cpu_after=$(< "$cpu_file")
        cpu_before_us=$((cpu_before / 1000))
        cpu_after=$((cpu_after / 1000))
    fi
    if [[ "$cpu_after" =~ ^[0-9]+$ && "$cpu_before_us" =~ ^[0-9]+$ && $cpu_after -ge $cpu_before_us ]]; then
        record "cgroup_cpu_usage_delta_usec=$((cpu_after - cpu_before_us))"
    else
        record "cgroup_cpu_usage_delta_usec=unavailable"
    fi
else
    record "cgroup_cpu_usage_delta_usec=unavailable"
fi

if [[ -n "$oom_before" && -r "$events_file" ]]; then
    oom_after=$(counter "$events_file" oom_kill) || oom_after=
    if [[ "$oom_after" =~ ^[0-9]+$ && $oom_after -ge $oom_before ]]; then
        record "cgroup_oom_kill_delta=$((oom_after - oom_before))"
    else
        record "cgroup_oom_kill_delta=unavailable"
    fi
else
    record "cgroup_oom_kill_delta=unavailable"
fi

record "ctest_exit_code=${statuses[0]}"
if [[ ${statuses[1]} -ne 0 ]]; then
    record "ctest_log_write_exit_code=${statuses[1]}"
fi

if [[ ${statuses[0]} -ne 0 ]]; then
    exit "${statuses[0]}"
fi
if [[ $sampling_failed -ne 0 ]]; then
    exit 1
fi
exit "${statuses[1]}"
