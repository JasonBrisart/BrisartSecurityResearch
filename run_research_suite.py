"""Configurable research test runner for BrisartSecurityResearch.

This suite measures deterministic behavior, tamper detection, diffusion,
simple output statistics, collision observations, and throughput. Passing it
does not establish cryptographic security.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from brisart_security_drbg import BrisartDRBG
from brisart_security_envelope import BrisartEnvelopeError, decrypt, encrypt
from brisart_security_primitives import keyed_mac, sponge_hash, stream_bytes


@dataclass
class Result:
    category: str
    name: str
    status: str
    trials: int
    duration_seconds: float
    metrics: dict
    note: str


class Suite:
    def __init__(self, config: dict):
        self.config = config
        self.random = random.Random(config["deterministic_seed"])
        self.results: list[Result] = []

    def bytes(self, length: int) -> bytes:
        return bytes(self.random.getrandbits(8) for _ in range(length))

    def run(self, category: str, name: str, trials: int, function: Callable[[], tuple[bool, dict, str]]) -> None:
        started = time.perf_counter()
        try:
            passed, metrics, note = function()
            status = "PASS" if passed else "FAIL"
        except Exception as exc:
            status = "ERROR"
            metrics = {"exception_type": type(exc).__name__}
            note = str(exc)
        elapsed = time.perf_counter() - started
        self.results.append(Result(category, name, status, trials, elapsed, metrics, note))
        print(f"[{status:5}] {category}: {name} ({elapsed:.3f}s)")

    def hash_avalanche(self):
        cfg = self.config["hash"]
        distances = []
        for _ in range(cfg["avalanche_trials"]):
            size = self.random.choice(cfg["message_sizes"])
            message = bytearray(self.bytes(size))
            changed = bytearray(message)
            bit = self.random.randrange(size * 8)
            changed[bit // 8] ^= 1 << (bit % 8)
            left = sponge_hash(bytes(message))
            right = sponge_hash(bytes(changed))
            distances.append(sum((a ^ b).bit_count() for a, b in zip(left, right)) / 256)
        mean = statistics.fmean(distances)
        metrics = {
            "mean_changed_bit_ratio": mean,
            "minimum_changed_bit_ratio": min(distances),
            "maximum_changed_bit_ratio": max(distances),
            "population_standard_deviation": statistics.pstdev(distances),
        }
        passed = cfg["avalanche_mean_min"] <= mean <= cfg["avalanche_mean_max"]
        return passed, metrics, "Observational diffusion test; not a proof of resistance to cryptanalysis."

    def hash_collisions(self):
        count = self.config["hash"]["collision_trials"]
        seen = set()
        collisions = 0
        for index in range(count):
            message = index.to_bytes(8, "big") + self.bytes(self.random.randint(0, 256))
            digest = sponge_hash(message)
            if digest in seen:
                collisions += 1
            seen.add(digest)
        return collisions == 0, {"observed_collisions": collisions, "unique_digests": len(seen)}, "No observed collisions does not establish collision resistance."

    def hash_domain_separation(self):
        count = self.config["hash"]["domain_separation_trials"]
        equal = 0
        for index in range(count):
            message = self.bytes(self.random.randint(0, 256))
            a = sponge_hash(message, domain=b"BRC1/test/domain/a/" + index.to_bytes(4, "big"))
            b = sponge_hash(message, domain=b"BRC1/test/domain/b/" + index.to_bytes(4, "big"))
            equal += a == b
        return equal == 0, {"equal_cross_domain_outputs": equal}, "Checks observed separation for explicit test domains."

    def mac_tamper(self):
        count = self.config["mac"]["tamper_trials"]
        unchanged = 0
        for _ in range(count):
            key = self.bytes(32)
            message = bytearray(self.bytes(self.random.randint(1, 512)))
            original = keyed_mac(key, bytes(message))
            bit = self.random.randrange(len(message) * 8)
            message[bit // 8] ^= 1 << (bit % 8)
            unchanged += original == keyed_mac(key, bytes(message))
        return unchanged == 0, {"undetected_message_mutations": unchanged}, "Mutation observation only; not a forgery-resistance proof."

    def mac_domain_separation(self):
        count = self.config["mac"]["domain_trials"]
        equal = 0
        for index in range(count):
            key = self.bytes(32)
            message = self.bytes(self.random.randint(0, 256))
            a = keyed_mac(key, b"domain-a" + index.to_bytes(4, "big") + message)
            b = keyed_mac(key, b"domain-b" + index.to_bytes(4, "big") + message)
            equal += a == b
        return equal == 0, {"equal_labeled_outputs": equal}, "Tests caller-supplied labels in MAC inputs."

    def stream_unique_blocks(self):
        count = self.config["stream"]["unique_block_trials"]
        key = self.bytes(32)
        blocks = set()
        duplicates = 0
        for index in range(count):
            nonce = index.to_bytes(32, "big")
            block = stream_bytes(key, nonce, 64)
            duplicates += block in blocks
            blocks.add(block)
        return duplicates == 0, {"duplicate_blocks": duplicates, "unique_blocks": len(blocks)}, "No observed duplicates does not establish stream indistinguishability."

    def stream_statistics(self):
        cfg = self.config["stream"]
        sample = stream_bytes(self.bytes(32), self.bytes(32), cfg["sample_bytes"])
        one_bits = sum(value.bit_count() for value in sample)
        ones_ratio = one_bits / (len(sample) * 8)
        xs = sample[:-1]
        ys = sample[1:]
        mean_x = statistics.fmean(xs)
        mean_y = statistics.fmean(ys)
        numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
        denominator = math.sqrt(sum((x - mean_x) ** 2 for x in xs) * sum((y - mean_y) ** 2 for y in ys))
        correlation = numerator / denominator if denominator else 0.0
        passed = (
            cfg["ones_ratio_min"] <= ones_ratio <= cfg["ones_ratio_max"]
            and abs(correlation) <= cfg["max_absolute_serial_correlation"]
        )
        return passed, {"sample_bytes": len(sample), "ones_ratio": ones_ratio, "adjacent_byte_serial_correlation": correlation}, "Simple output statistics are diagnostic only."

    def drbg_determinism(self):
        cfg = self.config["drbg"]
        mismatches = 0
        for index in range(cfg["determinism_trials"]):
            seed = self.bytes(64)
            label = b"BRC1 intermediate determinism" + index.to_bytes(4, "big")
            additional = b"request/" + index.to_bytes(4, "big")
            a = BrisartDRBG(seed, label).generate(cfg["output_bytes_per_trial"], additional)
            b = BrisartDRBG(seed, label).generate(cfg["output_bytes_per_trial"], additional)
            mismatches += a != b
        return mismatches == 0, {"determinism_mismatches": mismatches}, "Same complete input and call sequence should reproduce output."

    def drbg_seed_sensitivity(self):
        cfg = self.config["drbg"]
        equal = 0
        distances = []
        for index in range(cfg["seed_sensitivity_trials"]):
            seed_a = bytearray(self.bytes(64))
            seed_b = bytearray(seed_a)
            bit = self.random.randrange(len(seed_b) * 8)
            seed_b[bit // 8] ^= 1 << (bit % 8)
            label = b"BRC1 intermediate sensitivity" + index.to_bytes(4, "big")
            additional = b"request/" + index.to_bytes(4, "big")
            a = BrisartDRBG(bytes(seed_a), label).generate(cfg["output_bytes_per_trial"], additional)
            b = BrisartDRBG(bytes(seed_b), label).generate(cfg["output_bytes_per_trial"], additional)
            equal += a == b
            distances.append(sum((x ^ y).bit_count() for x, y in zip(a, b)) / (len(a) * 8))
        return equal == 0, {"equal_outputs": equal, "mean_changed_bit_ratio": statistics.fmean(distances)}, "Sensitivity observation only."

    def envelope_round_trip(self):
        cfg = self.config["envelope"]
        failures = 0
        total_bytes = 0
        master = self.bytes(32)
        for index in range(cfg["round_trip_trials"]):
            size = self.random.randint(0, cfg["maximum_random_plaintext_bytes"])
            plaintext = self.bytes(size)
            total_bytes += size
            seed = hashlib.sha512(b"roundtrip" + index.to_bytes(8, "big")).digest()
            context = f"research-suite:roundtrip:{index}"
            envelope = encrypt(master, plaintext, context, BrisartDRBG(seed, b"BRC1 research suite roundtrip"))
            failures += decrypt(master, envelope, context) != plaintext
        return failures == 0, {"round_trip_failures": failures, "total_plaintext_bytes": total_bytes}, "Behavioral correctness test across deterministic randomized lengths."

    def envelope_tamper(self):
        cfg = self.config["envelope"]
        master = self.bytes(32)
        undetected = 0
        fields = ("salt", "nonce", "ciphertext", "tag")
        for index in range(cfg["tamper_trials"]):
            plaintext = self.bytes(self.random.randint(1, min(1024, cfg["maximum_random_plaintext_bytes"])))
            seed = hashlib.sha512(b"tamper" + index.to_bytes(8, "big")).digest()
            context = f"research-suite:tamper:{index}"
            envelope = encrypt(master, plaintext, context, BrisartDRBG(seed, b"BRC1 research suite tamper"))
            field = fields[index % len(fields)]
            raw = bytearray.fromhex(envelope[field])
            raw[self.random.randrange(len(raw))] ^= 1 << self.random.randrange(8)
            envelope[field] = raw.hex()
            try:
                decrypt(master, envelope, context)
                undetected += 1
            except BrisartEnvelopeError:
                pass
        return undetected == 0, {"undetected_envelope_mutations": undetected}, "Tamper-detection observation; not a forgery-resistance proof."

    def envelope_wrong_context(self):
        count = self.config["envelope"]["wrong_context_trials"]
        master = self.bytes(32)
        accepted = 0
        for index in range(count):
            seed = hashlib.sha512(b"context" + index.to_bytes(8, "big")).digest()
            envelope = encrypt(master, self.bytes(64), f"context:{index}", BrisartDRBG(seed, b"BRC1 context rejection test"))
            try:
                decrypt(master, envelope, f"context:{index}:wrong")
                accepted += 1
            except BrisartEnvelopeError:
                pass
        return accepted == 0, {"wrong_context_acceptances": accepted}, "Checks that context is authenticated."

    def envelope_wrong_key(self):
        count = self.config["envelope"]["wrong_key_trials"]
        accepted = 0
        for index in range(count):
            master = self.bytes(32)
            wrong = self.bytes(32)
            seed = hashlib.sha512(b"wrong-key" + index.to_bytes(8, "big")).digest()
            context = f"wrong-key:{index}"
            envelope = encrypt(master, self.bytes(64), context, BrisartDRBG(seed, b"BRC1 wrong key rejection"))
            try:
                decrypt(wrong, envelope, context)
                accepted += 1
            except BrisartEnvelopeError:
                pass
        return accepted == 0, {"wrong_key_acceptances": accepted}, "Checks observed rejection under unrelated keys."

    def performance_hash(self):
        cfg = self.config["performance"]
        rows = []
        for size, repetitions in zip(cfg["hash_message_sizes"], cfg["hash_repetitions"]):
            message = self.bytes(size)
            started = time.perf_counter()
            for _ in range(repetitions):
                sponge_hash(message)
            elapsed = time.perf_counter() - started
            rows.append({"message_bytes": size, "repetitions": repetitions, "bytes_per_second": size * repetitions / elapsed})
        return True, {"measurements": rows}, "Local runtime measurement; machine and interpreter dependent."

    def performance_envelope(self):
        cfg = self.config["performance"]
        master = self.bytes(32)
        rows = []
        for size, repetitions in zip(cfg["envelope_message_sizes"], cfg["envelope_repetitions"]):
            plaintext = self.bytes(size)
            generator = BrisartDRBG(hashlib.sha512(b"perf" + size.to_bytes(8, "big")).digest(), b"BRC1 performance test")
            started = time.perf_counter()
            for index in range(repetitions):
                context = f"performance:{size}:{index}"
                envelope = encrypt(master, plaintext, context, generator)
                decrypt(master, envelope, context)
            elapsed = time.perf_counter() - started
            rows.append({"message_bytes": size, "repetitions": repetitions, "round_trip_bytes_per_second": size * repetitions / elapsed})
        return True, {"measurements": rows}, "Combined encrypt/decrypt local runtime measurement."

    def execute(self):
        h, m, s, d, e, p = (self.config[name] for name in ("hash", "mac", "stream", "drbg", "envelope", "performance"))
        self.run("hash", "single-bit avalanche", h["avalanche_trials"], self.hash_avalanche)
        self.run("hash", "collision observation", h["collision_trials"], self.hash_collisions)
        self.run("hash", "domain separation", h["domain_separation_trials"], self.hash_domain_separation)
        self.run("mac", "message tamper sensitivity", m["tamper_trials"], self.mac_tamper)
        self.run("mac", "labeled input separation", m["domain_trials"], self.mac_domain_separation)
        self.run("stream", "unique nonce blocks", s["unique_block_trials"], self.stream_unique_blocks)
        self.run("stream", "bit balance and serial correlation", s["sample_bytes"], self.stream_statistics)
        self.run("drbg", "determinism", d["determinism_trials"], self.drbg_determinism)
        self.run("drbg", "single-bit seed sensitivity", d["seed_sensitivity_trials"], self.drbg_seed_sensitivity)
        self.run("envelope", "randomized round trips", e["round_trip_trials"], self.envelope_round_trip)
        self.run("envelope", "binary field tamper rejection", e["tamper_trials"], self.envelope_tamper)
        self.run("envelope", "wrong context rejection", e["wrong_context_trials"], self.envelope_wrong_context)
        self.run("envelope", "wrong key rejection", e["wrong_key_trials"], self.envelope_wrong_key)
        self.run("performance", "hash throughput", sum(p["hash_repetitions"]), self.performance_hash)
        self.run("performance", "envelope round-trip throughput", sum(p["envelope_repetitions"]), self.performance_envelope)


def write_outputs(config: dict, results: list[Result], output_dir: Path, baseline: dict | None = None) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).isoformat()
    payload = {
        "generated_utc": generated,
        "warning": "Passing results do not establish cryptographic security.",
        "configuration": config,
        "baseline_unittest": baseline,
        "summary": {
            "pass": sum(r.status == "PASS" for r in results),
            "fail": sum(r.status == "FAIL" for r in results),
            "error": sum(r.status == "ERROR" for r in results),
            "total": len(results),
            "total_duration_seconds": sum(r.duration_seconds for r in results),
        },
        "results": [asdict(result) for result in results],
    }
    (output_dir / "research_test_results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    with (output_dir / "research_test_results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["category", "name", "status", "trials", "duration_seconds", "metrics", "note"])
        for result in results:
            writer.writerow([result.category, result.name, result.status, result.trials, f"{result.duration_seconds:.6f}", json.dumps(result.metrics, sort_keys=True), result.note])

    summary = payload["summary"]
    lines = [
        "# BrisartSecurityResearch Test Results",
        "",
        f"Generated UTC: `{generated}`",
        f"Profile: `{config['profile_name']}`",
        "",
        "> Passing these tests demonstrates only the measured behavior. It does not establish cryptographic security, production suitability, or resistance to cryptanalysis.",
        "",
        "## Summary",
        "",
        f"- Research checks: {summary['total']}",
        f"- Passed: {summary['pass']}",
        f"- Failed: {summary['fail']}",
        f"- Errors: {summary['error']}",
        f"- Research-suite runtime: {summary['total_duration_seconds']:.3f} seconds",
    ]
    if baseline:
        lines += [
            f"- Original unittest checks: {baseline['tests_run']}",
            f"- Original unittest failures: {baseline['failures']}",
            f"- Original unittest errors: {baseline['errors']}",
            f"- Original unittest runtime: {baseline['duration_seconds']:.3f} seconds",
        ]
    lines += ["", "## Detailed Results", ""]
    for result in results:
        lines += [
            f"### {result.status}: {result.category} / {result.name}",
            "",
            f"- Trials or sample units: {result.trials}",
            f"- Duration: {result.duration_seconds:.3f} seconds",
            f"- Metrics: `{json.dumps(result.metrics, sort_keys=True)}`",
            f"- Note: {result.note}",
            "",
        ]
    (output_dir / "research_test_results.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run configurable Brisart cryptographic research tests.")
    parser.add_argument("--config", default="research_test_config.json", help="Path to JSON configuration.")
    parser.add_argument("--baseline-json", default="results/baseline_unittest_results.json", help="Optional baseline unittest result JSON.")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    suite = Suite(config)
    suite.execute()
    baseline_path = Path(args.baseline_json)
    baseline = json.loads(baseline_path.read_text(encoding="utf-8")) if baseline_path.exists() else None
    write_outputs(config, suite.results, Path(config["output_directory"]), baseline)
    return 1 if any(result.status != "PASS" for result in suite.results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
