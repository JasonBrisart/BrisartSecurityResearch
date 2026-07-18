# BrisartSecurityResearch

Dependency-free, pure-Python research into custom cryptographic constructions for offline and air-gapped environments.

> [!WARNING]
> **Experimental research only.** This repository contains custom cryptographic constructions that have not undergone independent cryptanalysis, formal verification, certification, or production security review. Do not use this project as the sole protection for credentials, biometric data, personal information, sensitive research, access-control decisions, or other valuable data.

## Purpose

BrisartSecurityResearch explores a small, inspectable cryptographic construction implemented with base Python and no third-party packages.

The current repository focuses only on the experimental encryption stack:

- a custom 1024-bit permutation
- a custom sponge-style hash construction
- a custom keyed authentication construction
- a custom password-derived key experiment
- purpose-separated subkey derivation
- a custom deterministic random-bit generator
- custom stream generation
- an encrypt-then-authenticate envelope format
- deterministic behavioral and tamper tests

## Repository Layout

```text
BrisartSecurityResearch/
├── brisart_security_primitives.py
├── brisart_security_drbg.py
├── brisart_security_envelope.py
├── test_brisart_security.py
└── README.md
```

## Component Overview

### `brisart_security_primitives.py`

Contains the custom permutation, sponge construction, keyed authentication construction, password-derived key experiment, subkey derivation, stream generation, XOR transformation, comparison routine, and hexadecimal codec.

### `brisart_security_drbg.py`

Contains the custom deterministic random-bit generator used to expand caller-provided seed material.

The generator does not create entropy. The same seed, personalization, additional input, and call sequence reproduce the same output.

### `brisart_security_envelope.py`

Contains the versioned authenticated envelope. The current construction derives separate encryption and authentication keys, generates a stream, transforms plaintext with XOR, authenticates the envelope, and verifies authentication before returning plaintext.

### `test_brisart_security.py`

Contains deterministic behavioral tests for round trips, wrong keys, wrong contexts, field mutation, generator lifecycle behavior, reseeding, empty plaintext, encoding, and avalanche observation.

Passing these tests demonstrates only the behavior covered by the tests. It does not establish cryptographic security.

## Running the Tests

From the repository root:

```powershell
python test_brisart_security.py
```

## Entropy Boundary

The custom deterministic generator expands caller-provided seed material but cannot manufacture unpredictable physical entropy.

Any real security claim would depend on the quality, unpredictability, and secrecy of externally supplied seed material. This repository does not provide a validated entropy source.

## Known Limitations

The project has not established:

- collision resistance
- preimage resistance
- differential resistance
- rotational resistance
- algebraic resistance
- related-key resistance
- authentication-forgery resistance
- stream indistinguishability
- password-guessing resistance
- entropy-source validation
- state-compromise resistance
- side-channel resistance
- production security suitability

Python also does not guarantee complete erasure of immutable secret values from process memory.

## Intended Use

Appropriate uses include:

- controlled cryptographic research
- source-code inspection
- synthetic test data
- offline workflow prototypes
- parser and tamper-testing research
- educational analysis of custom constructions

## Unsupported Use

Do not rely on this repository as the sole protection for:

- passwords or credentials
- API keys or access tokens
- biometric templates
- recovery secrets
- personal information
- sensitive research records
- production authorization
- safety-critical or regulated systems

## Project Status

```text
Status: Experimental research
Maturity: Alpha
Production ready: No
Independently reviewed: No
Security certified: No
```

## License

Licensing and ecosystem policy are governed by the applicable terms in the Brisart licensing repository. Licensing permission does not imply production security suitability.
