# BrisartSecurityResearch Test Results

Generated UTC: `2026-07-18T19:55:29.138244+00:00`
Profile: `intermediate`

> Passing checks demonstrate only the measured behavior. They do not establish cryptographic security, production suitability, or resistance to cryptanalysis.

## Provenance

- Python: `CPython 3.14.6`
- Operating system: `Windows 11`
- Source revision: `unavailable`
- Uncommitted changes present: `false`
- Configuration SHA-256: `853d680e709b40e1fd66c107bac020ffa7c8a4e625f68dd29e1f4e860ca69c71`
- Known-answer vector SHA-256: `19e9576b9d04c37e17a7c2568753d36b45b7dd8072e63df5eacd70f67ca927f5`

## Summary

- Checks: 13
- Passed: 13
- Failed: 0
- Errors: 0
- Benchmarks completed: 2
- Total runtime: 65.910 seconds

## Detailed Results

### PASS: hash / single-bit avalanche

- Trials or sample units: 128
- Duration: 1.113 seconds
- Metrics: `{"maximum_changed_bit_ratio": 0.58984375, "mean_changed_bit_ratio": 0.494537353515625, "minimum_changed_bit_ratio": 0.41796875, "population_standard_deviation": 0.029962092306469092}`
- Note: Observational diffusion test; not a proof of resistance to cryptanalysis.

### PASS: hash / collision observation

- Trials or sample units: 1000
- Duration: 5.761 seconds
- Metrics: `{"observed_collisions": 0, "unique_digests": 1000}`
- Note: No observed collisions does not establish collision resistance.

### PASS: hash / domain separation

- Trials or sample units: 64
- Duration: 0.716 seconds
- Metrics: `{"equal_cross_domain_outputs": 0}`
- Note: Checks observed separation for explicit test domains.

### PASS: mac / message tamper sensitivity

- Trials or sample units: 128
- Duration: 6.286 seconds
- Metrics: `{"undetected_message_mutations": 0}`
- Note: Mutation observation only; not a forgery-resistance proof.

### PASS: mac / labeled input separation

- Trials or sample units: 64
- Duration: 2.392 seconds
- Metrics: `{"equal_labeled_outputs": 0}`
- Note: Tests caller-supplied labels in MAC inputs.

### PASS: stream / unique nonce blocks

- Trials or sample units: 256
- Duration: 3.455 seconds
- Metrics: `{"duplicate_blocks": 0, "unique_blocks": 256}`
- Note: No observed duplicates does not establish stream indistinguishability.

### PASS: stream / bit balance and serial correlation

- Trials or sample units: 8192
- Duration: 1.741 seconds
- Metrics: `{"adjacent_byte_serial_correlation": 0.01366547073769677, "ones_ratio": 0.499603271484375, "sample_bytes": 8192}`
- Note: Simple output statistics are diagnostic only.

### PASS: drbg / determinism

- Trials or sample units: 64
- Duration: 4.710 seconds
- Metrics: `{"determinism_mismatches": 0}`
- Note: Same complete input and call sequence should reproduce output.

### PASS: drbg / single-bit seed sensitivity

- Trials or sample units: 64
- Duration: 4.689 seconds
- Metrics: `{"equal_outputs": 0, "mean_changed_bit_ratio": 0.500762939453125}`
- Note: Sensitivity observation only.

### PASS: envelope / randomized round trips

- Trials or sample units: 16
- Duration: 4.839 seconds
- Metrics: `{"round_trip_failures": 0, "total_plaintext_bytes": 3931}`
- Note: Behavioral correctness test across deterministic randomized lengths.

### PASS: envelope / binary field tamper rejection

- Trials or sample units: 64
- Duration: 15.949 seconds
- Metrics: `{"undetected_envelope_mutations": 0}`
- Note: Tamper-detection observation; not a forgery-resistance proof.

### PASS: envelope / wrong context rejection

- Trials or sample units: 16
- Duration: 2.876 seconds
- Metrics: `{"wrong_context_acceptances": 0}`
- Note: Checks that context is authenticated.

### PASS: envelope / wrong key rejection

- Trials or sample units: 16
- Duration: 2.865 seconds
- Metrics: `{"wrong_key_acceptances": 0}`
- Note: Checks observed rejection under unrelated keys.

### BENCHMARK: performance / hash throughput

- Trials or sample units: 56
- Duration: 0.566 seconds
- Metrics: `{"measurements": [{"bytes_per_second": 10965.716371931268, "message_bytes": 32, "repetitions": 50}, {"bytes_per_second": 30435.627751650434, "message_bytes": 1024, "repetitions": 5}, {"bytes_per_second": 32943.059416119286, "message_bytes": 8192, "repetitions": 1}]}`
- Note: Local runtime measurement; machine and interpreter dependent.

### BENCHMARK: performance / envelope round-trip throughput

- Trials or sample units: 13
- Duration: 7.951 seconds
- Metrics: `{"measurements": [{"message_bytes": 32, "repetitions": 10, "round_trip_bytes_per_second": 177.33810734568428}, {"message_bytes": 1024, "repetitions": 2, "round_trip_bytes_per_second": 1442.330513088296}, {"message_bytes": 8192, "repetitions": 1, "round_trip_bytes_per_second": 1742.2187453594076}]}`
- Note: Combined encrypt/decrypt local runtime measurement.
