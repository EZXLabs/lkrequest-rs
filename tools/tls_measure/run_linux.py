"""Run one prebuilt timing test with an idle gate and retained Linux evidence."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time


BUILD_NAMES = {"cargo", "rustc", "clippy-driver", "cc1", "cc1plus", "clang", "ld.lld"}


def builds():
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            name = (entry / "comm").read_text().strip()
        except (OSError, UnicodeError):
            continue
        if name in BUILD_NAMES:
            found.append({"pid": int(entry.name), "name": name})
    return found


def cpu_times():
    result = {}
    with Path("/proc/stat").open() as source:
        for line in source:
            fields = line.split()
            if not fields or not fields[0].startswith("cpu"):
                continue
            # guest/guest_nice are already included in user/nice.
            result[fields[0]] = [int(value) for value in fields[1:9]]
    return result


def cpu_delta(before, after):
    result = {}
    for name in before.keys() & after.keys():
        values = [b - a for a, b in zip(before[name], after[name])]
        total = sum(values)
        if total <= 0 or min(values) < 0:
            continue
        result[name] = {
            "busy_percent": 100 * (total - values[3] - values[4] - values[7]) / total,
            "idle_percent": 100 * values[3] / total,
            "iowait_percent": 100 * values[4] / total,
            "steal_percent": 100 * values[7] / total,
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("test")
    parser.add_argument("output_prefix", type=Path)
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--idle-samples", type=int, default=5)
    parser.add_argument("--max-idle-cpu", type=float, default=5)
    parser.add_argument("--max-idle-steal", type=float, default=0.5)
    parser.add_argument("--timeout", type=float, default=1200)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("requires Linux /proc and taskset")
    import resource

    if args.idle_samples < 1 or args.timeout <= 0:
        parser.error("idle samples and timeout must be positive")
    if args.cpu is not None and args.cpu not in os.sched_getaffinity(0):
        parser.error("requested logical CPU is unavailable")
    executable = args.executable.resolve(strict=True)
    paths = {name: Path(str(args.output_prefix) + suffix) for name, suffix in
             (("stdout", ".log"), ("stderr", ".stderr.log"), ("metadata", ".metadata.json"))}
    if not args.output_prefix.parent.is_dir() or any(path.exists() for path in paths.values()):
        parser.error("output directory must exist and all output files must be new")
    observations = []
    previous = cpu_times()
    metadata = {
        "executable": str(executable),
        "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "test": args.test,
        "logical_cpu": args.cpu,
        "allowed_cpus": sorted(os.sched_getaffinity(0)),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "preflight_policy": {"samples": args.idle_samples, "max_busy_percent": args.max_idle_cpu,
                             "max_steal_percent": args.max_idle_steal,
                             "checks_selected_cpu": args.cpu is not None},
        "platform": platform.uname()._asdict(),
        "environment": {key: value for key, value in os.environ.items()
                        if key.startswith(("TLS_RECORD_", "TLS_CLIENT_", "TLS_CONFIG_", "TLS_VERIFICATION_", "MALLOC_"))
                        or key == "GLIBC_TUNABLES"},
        "uid": os.getuid(),
        "effective_uid": os.geteuid(),
        "monitoring": "One-second process snapshots can miss short builds. CPU during execution includes the test. Review noise separately.",
        "observations": observations,
        "started_unix": None,
        "exit_code": None,
        "build_overlap_detected": False,
        "expected_single_test_passed": False,
    }
    try:
        for _ in range(args.idle_samples):
            time.sleep(1)
            current = cpu_times()
            observation = {"unix": time.time(), "phase": "preflight",
                           "cpu": cpu_delta(previous, current), "builds": builds()}
            observations.append(observation)
            previous = current
            checked = ["cpu"] + ([f"cpu{args.cpu}"] if args.cpu is not None else [])
            noisy = any(name not in observation["cpu"]
                        or observation["cpu"][name]["busy_percent"] > args.max_idle_cpu
                        or observation["cpu"][name]["steal_percent"] > args.max_idle_steal
                        for name in checked)
            if observation["builds"] or noisy:
                metadata["preflight_failed"] = True
                print("Idle/build preflight failed; no test launched.", flush=True)
                return 2
        command = [str(executable), args.test, "--exact", "--ignored", "--nocapture", "--test-threads=1"]
        if args.cpu is not None:
            command = ["taskset", "-c", str(args.cpu), *command]
        metadata["command"] = command
        metadata["started_unix"] = time.time()
        start = time.monotonic()
        usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        with paths["stdout"].open("xb") as output, paths["stderr"].open("xb") as error:
            with subprocess.Popen(command, stdout=output, stderr=error) as process:
                try:
                    while True:
                        try:
                            code = process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            code = None
                        current = cpu_times()
                        active = builds()
                        observations.append({"unix": time.time(), "phase": "running",
                                             "cpu": cpu_delta(previous, current), "builds": active})
                        previous = current
                        metadata["build_overlap_detected"] |= bool(active)
                        if code is not None:
                            metadata["exit_code"] = code
                            break
                        if time.monotonic() - start > args.timeout:
                            raise TimeoutError("measurement exceeded timeout")
                except BaseException:
                    process.kill()
                    process.wait()
                    raise
        metadata["ended_unix"] = time.time()
        usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        metadata["child_resource_usage"] = {
            "scope": "whole test process including setup, validation and destruction; not timed API segments",
            "user_cpu_seconds": usage_after.ru_utime - usage_before.ru_utime,
            "system_cpu_seconds": usage_after.ru_stime - usage_before.ru_stime,
            "minor_page_faults": usage_after.ru_minflt - usage_before.ru_minflt,
            "major_page_faults": usage_after.ru_majflt - usage_before.ru_majflt,
        }
        metadata["expected_single_test_passed"] = (
            "test result: ok. 1 passed; 0 failed;" in paths["stdout"].read_text())
        print(json.dumps({key: metadata[key] for key in
                          ("test", "exit_code", "build_overlap_detected", "expected_single_test_passed")}), flush=True)
        if metadata["exit_code"] or not metadata["expected_single_test_passed"]:
            return 1
        return 3 if metadata["build_overlap_detected"] else 0
    finally:
        with paths["metadata"].open("x") as destination:
            json.dump(metadata, destination, indent=2)
            destination.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
