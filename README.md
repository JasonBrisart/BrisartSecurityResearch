# BrisartSecurityResearch

Dependency-free, pure-Python research into custom cryptographic constructions for offline and air-gapped environments.

> [!WARNING]
> **Experimental research only.** This repository contains a custom cryptographic construction that has not undergone independent cryptanalysis, formal verification, certification, or production security review. Passing the included tests does not establish cryptographic security. Do not use this project as the sole protection for credentials, personal information, sensitive research, access-control decisions, recovery material, or other valuable data.

## Purpose

BrisartSecurityResearch is a small, inspectable research implementation built with the Python standard library and no third-party packages. BSR2 includes a custom 1024-bit permutation, sponge-style hash, keyed authentication construction, password-derived key experiment, subkey derivation, deterministic random-bit generator, counter-based stream generation, and a versioned encrypt-then-authenticate envelope.

The core construction and committed fixed parameters are repository-defined. The parameter generator is included for reproducibility. These properties do not substitute for established cryptographic analysis.

## Status

- **Maturity:** Alpha
- **Research implementation:** BSR2
- **Envelope version:** 2
- **Intended use:** Controlled research and offline prototypes
- **Production ready:** No
- **Independently reviewed:** No
- **Security certified:** No

## Repository layout

```text
BrisartSecurityResearch/
├── .github/
│   └── workflows/
│       └── tests.yml
├── docs/
│   ├── BSR2_PARAMETER_GENERATION.md
│   ├── DESIGN.md
│   └── TESTING.md
├── research/
│   ├── research_test_config.json
│   └── run_research_suite.py
├── results/
├── tests/
│   ├── generate_test_vectors.py
│   ├── known_answer_vectors.json
│   ├── test_brisart_security.py
│   ├── test_bsr2_parameters.py
│   └── test_known_answer_vectors.py
├── tools/
│   └── generate_bsr2_parameters.py
├── .gitignore
├── brisart_security_drbg.py
├── brisart_security_envelope.py
├── brisart_security_primitives.py
├── CHANGELOG.md
├── LICENSE
├── README.md
└── SECURITY.md
```

## Core implementation

- `brisart_security_primitives.py` contains the permutation, sponge, keyed authentication, password-derived key experiment, subkey derivation, stream generation, XOR transformation, comparison routine, and hexadecimal codec.
- `brisart_security_drbg.py` contains the deterministic generator that expands caller-provided seed material. It does not create entropy.
- `brisart_security_envelope.py` contains the BSR2 authenticated envelope and verifies authentication before returning plaintext.

## Running validation

From the repository root:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
python research/run_research_suite.py --config research/research_test_config.json
```

Do not regenerate known-answer vectors during an ordinary test run. See [`docs/TESTING.md`](docs/TESTING.md) for the complete workflow.

## Parameter provenance

[`docs/BSR2_PARAMETER_GENERATION.md`](docs/BSR2_PARAMETER_GENERATION.md) documents the public seed and deterministic generator used to produce BSR2 fixed parameters. `tests/test_bsr2_parameters.py` verifies that regenerated parameters match the values embedded in the implementation.

## Research results

Running the research suite writes Markdown, JSON, and CSV reports into `results/`. These reports document observed behavior only. They do not demonstrate collision resistance, preimage resistance, stream indistinguishability, forgery resistance, side-channel resistance, or production suitability.

## Entropy boundary

The deterministic generator expands caller-provided seed material but cannot manufacture unpredictable physical entropy. Any real security property depends on the quality, unpredictability, secrecy, and lifecycle of externally supplied seed material.

## Appropriate uses

- controlled cryptographic research
- source-code inspection
- synthetic or disposable data
- offline workflow prototypes
- parser and tamper-handling research
- regression testing of the experimental format
- educational analysis of custom constructions

## Unsupported uses

Do not rely on this repository as the sole protection for passwords, credentials, API keys, access tokens, identity records, recovery secrets, personal or regulated information, valuable unpublished research, production authorization, or safety-critical systems.

## Documentation

- [`docs/DESIGN.md`](docs/DESIGN.md) describes the implemented construction.
- [`docs/BSR2_PARAMETER_GENERATION.md`](docs/BSR2_PARAMETER_GENERATION.md) documents fixed-parameter generation.
- [`docs/TESTING.md`](docs/TESTING.md) explains validation layers and vector policy.
- [`SECURITY.md`](SECURITY.md) defines the project security posture.
- [`CHANGELOG.md`](CHANGELOG.md) records project-level changes.

## Compatibility

BSR2 is intentionally incompatible with BSR1 ciphertext and vectors. Retain the frozen BSR1 backup separately if BSR1 material may need to be inspected or recovered.

## Licensing

This project is part of the Brisart ecosystem. The current licensing terms and ecosystem policies are maintained in the BrisartLicensing repository. See [`LICENSE`](LICENSE).

### Deterministic restart and reuse warning

Reinitializing `BrisartDRBG` with the same seed and personalization reproduces
its output sequence. Reusing the same master key, generator inputs, context,
and first request position can therefore reproduce salt, nonce, ciphertext,
and tag values. Applications must provide fresh unpredictable seed material or
safely persist generator state across restarts. Fixed seeds such as
`bytes(range(64))` are for tests and vectors only.
