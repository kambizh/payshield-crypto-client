# payshield-crypto-client

A Java-based client library for integrating with Thales payShield 10K HSM using native TCP host commands. This library abstracts low-level command handling and provides a simplified API for cryptographic operations such as key generation, digital signing, and CSR creation.

## Purpose

This project was developed as a Proof of Concept (POC) to demonstrate secure cryptographic operations using HSM. It focuses on delegating sensitive operations—such as private key usage—to the HSM, ensuring that private keys never leave the secure boundary.

## Supported Features

- RSA Key Pair Generation via HSM (`EI`)
- Digital Signature Generation via HSM (`EW`)
- Certificate Signing Request (CSR) generation via HSM (`QE`)
- Public key–based signature verification (application-side)
- Direct TCP communication with payShield 10K

## Architecture

The library encapsulates:

- HSM connection management (TCP-based)
- Command construction and parsing
- Cryptographic operation abstraction
- Basic error handling and response interpretation

All HSM-specific details (command codes, binary formats) are hidden behind a simple Java API.

## Scope & Limitations

- This is a **POC-level implementation**, not production-ready
- Limited error handling and retry mechanisms
- No full key lifecycle management (e.g., rotation, archival)
- No integration with CA or certificate lifecycle systems
- Verification is performed outside HSM for simplicity
