# Testing Guide

BrisartSecurityResearch uses three separate testing layers. Each layer answers a different question, and none establishes cryptographic security.

## 1. Behavioral unit tests

File:

```text
tests/test_brisart_security.py
```

These tests cover implemented behavior such as:

- encryption and decryption round trips
- randomized envelope output
- mutation rejection for salt, nonce, ciphertext, and tag
- wrong-key and wrong-context rejection
- malformed envelope fields
- empty plaintext
- hexadecimal encoding and decoding
- deterministic hash behavior
- a basic avalanche observation
- DRBG determinism, input validation, reseeding, and destroyed-state behavior

Run from the repository root:

```bash
python -m unittest -v tests.test_brisart_security
```

## 2. Frozen known-answer regression tests

Files:

```text
tests/test_known_answer_vectors.py
tests/known_answer_vectors.json
```

The JSON file contains expected outputs for the hash, MAC, stream generator, DRBG, and complete envelope. The test verifies that the current implementation still produces those exact outputs.

Run:

```bash
python -m unittest -v tests.test_known_answer_vectors
```

### Vector policy

Do not regenerate vectors before an ordinary test run. Doing so would replace the expected answers and could hide an accidental algorithm change.

Run the vector generator only when intentionally changing the algorithm or envelope format:

```bash
python generate_test_vectors.py
```

Review vector changes separately. An intentional vector change should be accompanied by a version decision, documentation update, changelog entry, and fresh research results.

## 3. Configurable research suite

Files:

```text
run_research_suite.py
research_test_config.json
```

Run:

```bash
python run_research_suite.py --config research_test_config.json
```

The suite writes its current reports into:

```text
results/research_test_results.md
results/research_test_results.json
results/research_test_results.csv
```

The configuration controls trial counts, message sizes, deterministic seed, statistical boundaries, output sample size, and benchmark repetitions.

## Complete local test sequence

```bash
python -m unittest discover -s tests -p "test_*.py" -v
python run_research_suite.py --config research_test_config.json
```

## Interpreting results

Behavioral and known-answer passes establish that the tested implementation behaved as expected for the supplied cases.

Research-suite observations can expose obvious regressions, repeated outputs, poor diffusion, malformed-envelope acceptance, or unexpected local statistics. They do not establish:

- collision resistance
- preimage resistance
- pseudorandomness
- stream indistinguishability
- authentication-forgery resistance
- password-guessing resistance
- side-channel resistance
- production security

Performance measurements are informational benchmarks. They are machine- and interpreter-dependent and should not be described as security passes.

## Continuous integration

The GitHub Actions workflow compiles the source and test files, runs both unittest modules, and runs the configurable research suite. The workflow must not regenerate known-answer vectors.

## Updating committed results

Commit fresh reports after a deliberate implementation or configuration change. The report, configuration, source revision, and known-answer vectors should describe the same implementation state.
