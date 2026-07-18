# Changelog

All notable project-level changes to BrisartSecurityResearch are recorded in this document.

This repository contains experimental research software.

A changelog entry records implementation history and design evolution. A changelog entry does not imply cryptographic validation, certification, production approval, or security guarantees.

---

# 0.2.0-alpha
## BSR2 Alpha 2

Release status:

```text
Current experimental release
```

This release introduces the BSR2 implementation and replaces the historical BSR1 construction.

---

## Added

### Core Construction

- Added the BSR2 custom 1024-bit permutation.
- Added a 16-word, 64-bit-per-word state design.
- Added repository-generated fixed parameters.
- Added repository-generated round constants.
- Added repository-generated structural mixing constants.
- Added repository-generated rotation values.
- Added repository-generated word permutation values.

### Parameter Infrastructure

Added:

```text
tools/generate_bsr2_parameters.py
```

for deterministic and reproducible parameter generation.

Added:

```text
docs/BSR2_PARAMETER_GENERATION.md
```

to document:

- Public parameter seed
- Generation procedure
- Reproducibility model
- Design limitations

Added:

```text
tests/test_bsr2_parameters.py
```

to verify that generated parameters exactly match the values embedded in:

```text
brisart_security_primitives.py
```

### Validation

Added explicit verification of:

- Envelope algorithm identifier
- Envelope version
- Known-answer vector format version

Added expanded behavioral and boundary testing covering:

- Envelope parsing
- Envelope validation
- Primitive validation
- Hexadecimal validation
- Size limits
- DRBG lifecycle limits

### Research Reporting

Added provenance metadata to generated research reports including:

- Python version
- Python implementation
- Operating system
- Git revision when available
- Configuration hash
- Known-answer vector hash

---

## Changed

### BSR1 → BSR2 Migration

Changed the algorithm identifier from:

```text
BSR1-ARX-SPONGE-ETM
```

to:

```text
BSR2-ARX-SPONGE-ETM
```

Changed the envelope version from:

```text
1
```

to:

```text
2
```

Replaced inherited fixed parameters with parameters generated directly by the BSR2 repository generator.

Updated active domain strings across:

- Hashing
- Message authentication
- Password-derived key generation
- DRBG operations
- Stream generation
- Subkey derivation
- Envelope operations

### Regression Data

Regenerated:

```text
tests/known_answer_vectors.json
```

for the incompatible BSR2 construction.

Updated unsupported-version tests to derive invalid version values from the active implementation rather than relying on hardcoded values.

### Research Suite

Changed throughput measurements from:

```text
PASS
```

to:

```text
BENCHMARK
```

to separate performance observations from behavioral validation.

### Workflow And Documentation

Updated the GitHub Actions workflow to:

- Compile source files
- Compile tools
- Compile tests
- Verify BSR2 parameters
- Execute automated test coverage

Updated documentation for:

```text
docs/
research/
results/
tests/
tools/
```

---

## Hardened

### Generator Validation

Added validation that generator-produced:

- Salt values are bytes
- Nonce values are bytes
- Salt values are exactly 32 bytes
- Nonce values are exactly 32 bytes
- Salt and nonce values are not identical

### Behavioral Testing

Added regression tests covering:

- Malformed generators
- Invalid generator outputs
- Generator-output length validation
- Generator-output type validation
- Deterministic restart and reuse behavior

### Research Infrastructure

Anchored research output paths to the repository layout so results are generated in the expected location regardless of the current working directory.

Improved Git provenance handling by reporting:

```text
unavailable
```

when repository state cannot be determined instead of incorrectly reporting:

```text
false
```

### Documentation

Added documentation describing:

- Deterministic generator restart and reuse risks
- Comparison-routine limitations
- Generator-output validation requirements

---

## Compatibility

BSR2 is intentionally incompatible with:

- BSR1 ciphertext
- BSR1 known-answer vectors
- BSR1 domain strings
- BSR1 fixed parameters
- BSR1 envelope metadata

Historical BSR1 archives should be retained separately if BSR1 material must be inspected, reproduced, or analyzed.

---

## Validation Status

Included validation layers:

- Behavioral tests
- Boundary tests
- Parameter reproducibility tests
- Known-answer regression tests

The configurable research suite includes:

- Diffusion observations
- Collision observations
- Domain-separation observations
- Message-tamper checks
- Stream-output statistics
- DRBG observations
- Envelope validation checks
- Local performance benchmarks

Passing tests establish only the behavior measured by the corresponding implementation and test suite.

BSR2 has not undergone:

- Independent cryptanalysis
- Formal verification
- Third-party certification
- Production-security review

---

# 0.1.0-alpha
## BSR1 Alpha 1

Release status:

```text
Historical release
```

### Added

- Initial BSR1 custom permutation experiment.
- Initial sponge-style hash construction.
- Initial keyed authentication construction.
- Initial password-derived key experiment.
- Purpose-separated subkey derivation.
- Deterministic random-bit generator.
- Counter-based stream generation.
- Version 1 authenticated envelope.
- Behavioral testing.
- Boundary testing.
- Mutation testing.
- Known-answer testing.
- Statistical observations.
- Performance observations.
- Markdown report generation.
- JSON report generation.
- CSV report generation.

### Status

```text
Historical experimental alpha
```

- Superseded by BSR2 Alpha 2.
- Not production ready.
- Not independently reviewed.
- Not security certified.