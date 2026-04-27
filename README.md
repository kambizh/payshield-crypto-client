# payshield-crypto-client

A Java-based client library for integrating with Thales payShield 10K HSM using native TCP host commands. This library abstracts low-level command handling and provides a simplified API for cryptographic operations such as RSA key generation, digital signing, and signature verification.

## Purpose

This project demonstrates secure cryptographic operations delegated to the HSM, ensuring that RSA private keys never leave the HSM's secure boundary in cleartext.

The library is designed to be consumed as an embedded JAR dependency.

## Supported HSM Commands

| Command | Description | Status |
|---------|-------------|--------|
| `EI` (→ `EJ`) | Generate RSA Key Pair |  Working |
| `EW` (→ `EX`) | Generate Digital Signature (inline private key, flag 99) |  Working |
| `EO` (→ `EP`) | Import Public Key (generates MAC for verification) |  Working |
| `EY` (→ `EZ`) | Validate Digital Signature (using imported public key + MAC) |  Working |
| `NC` (→ `ND`) | Perform Diagnostics (LMK check value, firmware number) |  Working |
| `NO` (→ `NP`) | HSM Status (buffer size, TCP sockets, firmware) |  Working |
| `LA` (→ `LB`) | Load Data to User Storage (private key storage for K000 reference) |  Planned |
| `QE` (→ `QF`) | Generate Certificate Signing Request (with Bouncy Castle TBS) |  Planned |

## Tested Environment

- **HSM**: Thales payShield 10K
- **Firmware**: 2200-1011 (version 2.2b)
- **Port**: 1501 (3DES Variant LMK)
- **LMK Type**: TDES Variant LMK (LMK check value: `9D04A00000000000`)
- **Key Size**: RSA-2048 (Key Type 0 = Signature)
- **Hash Algorithm**: SHA-256 (ID: `06`)
- **Pad Mode**: PKCS#1 v1.5 (ID: `01`)
- **I/O Buffer**: 32K bytes

> **Note on ports**: Port 1502 (Key Block LMK / AES) requires additional `#` delimiter fields in commands like EI. This POC uses port 1501 (Variant LMK) which follows the standard V1.7a command format.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    POC WebApp                       │
│            (Spring Boot Application)                │
└──────────────────────┬──────────────────────────────┘
                       │ Java API calls
┌──────────────────────▼──────────────────────────────┐
│              payshield-crypto-client                │
│               (Embedded JAR Library)                │
│                                                     │
│  ┌─────────────────┐  ┌──────────────────────────┐  │
│  │ HsmCryptoService│  │ Command Builders/Parsers │  │
│  │  (orchestrator) │  │  EI, EW, EO, EY, NC, NO  │  │
│  └────────┬────────┘  └──────────────────────────┘  │
│           │                                         │
│  ┌────────▼────────────────────────────────────────┐│
│  │ PayShieldConnectionPool (Commons Pool2)         ││
│  │  └─ PayShieldConnection (TCP + 2-byte framing)  ││
│  └─────────────────────────────────────────────────┘│
└──────────────────────┬──────────────────────────────┘
                       │ TCP socket (2-byte length prefix)
              ┌────────▼────────┐
              │ payShield 10K   │
              │  HSM Hardware   │
              │  (port 1501)    │
              └─────────────────┘
```

The library encapsulates:

- **Connection management** — TCP socket with 2-byte big-endian length-prefix framing, Apache Commons Pool2 connection pooling
- **Command construction** — Binary/ASCII command builders for each host command, with configurable message header
- **Response parsing** — Structured parsing of HSM responses including DER-encoded public keys, LMK-encrypted private keys, signatures, and MACs
- **Error handling** — HSM error code decoding with human-readable descriptions
- **Spring Boot auto-configuration** — Drop-in starter with `@ConfigurationProperties` support

## Key Flow (POC)

```
1. EI Command     → HSM generates RSA-2048 key pair internally
                  → Returns: Public key (DER) + Private key (LMK-encrypted blob)
                  → Application stores both in memory

2. EW Command     → Application sends message + LMK-encrypted private key (inline, flag 99)
                  → HSM decrypts private key under LMK, signs message, returns signature
                  → Private key decrypted ONLY inside HSM tamper-resistant boundary

3. EO + EY Commands → Import public key (EO) to get MAC from LMK pair 36-37
                    → Verify signature (EY) using public key + MAC + original message
                    → HSM returns: error code 00 (valid) or 02 (signature mismatch)
```

> **Important**: EI is stateless — the HSM does not retain the key pair after returning it. The LMK-encrypted private key blob must be stored by the application and passed back in each EW signing request.

## Configuration

Add to your `application.properties`:

```properties
# payShield 10K Connection
payshield.host=202.186.1.53
payshield.port=1501
payshield.header-length=4
payshield.connect-timeout-ms=5000
payshield.read-timeout-ms=15000
payshield.length-prefix-enabled=true

# Connection Pool
payshield.pool-max-total=3
payshield.pool-max-idle=2
payshield.pool-min-idle=1

# RSA Key Settings
payshield.default-modulus-length=2048
payshield.private-key-storage-index=000

# Crypto Defaults (SHA-256 + PKCS#1 v1.5 for PayNet RPP)
payshield.default-hash-id=06
payshield.default-sig-id=01
payshield.default-pad-mode=01
```

## Usage Example

```java
@Autowired
private HsmCryptoService hsmService;

// 1. Generate RSA key pair
KeyGenerationResult keyPair = hsmService.generateKeyPair(2048);
byte[] publicKeyDer = keyPair.getPublicKeyDer();
byte[] privateKeyBlob = keyPair.getPrivateKeyLmkEncrypted();

// 2. Sign a message
byte[] message = "PayNet RPP AutoDebit Message".getBytes(StandardCharsets.UTF_8);
SigningResult signing = hsmService.signMessage(message);
byte[] signature = signing.getSignature();

// 3. Verify a signature
VerificationResult result = hsmService.verifySignature(signature, message, publicKeyDer);
boolean isValid = result.isValid(); // true if signature matches
```

## Health check 

http://100.30.122.138:8080/api/hsm-status
http://100.30.122.138:8080/api/diagnostics

## Project Structure

```
payshield-crypto-client/
├── src/main/java/my/com/kambiz/hsm/
│   ├── command/           # HSM command builders and parsers
│   │   ├── CommandUtils.java          # Wire format utilities
│   │   ├── EICommand.java            # Generate RSA Key Pair
│   │   ├── EWCommand.java            # Generate Signature
│   │   ├── EOCommand.java            # Import Public Key
│   │   ├── EYCommand.java            # Validate Signature
│   │   ├── LACommand.java            # Load Data to User Storage (planned)
│   │   └── DiagnosticCommands.java   # NC + NO diagnostics
│   ├── config/            # Spring Boot auto-configuration
│   │   ├── PayShieldProperties.java
│   │   └── PayShieldAutoConfiguration.java
│   ├── connection/        # TCP connection and pooling
│   │   ├── PayShieldConnection.java
│   │   ├── PayShieldConnectionFactory.java
│   │   └── PayShieldConnectionPool.java
│   ├── exception/
│   │   └── PayShieldException.java
│   ├── model/             # Result objects
│   │   ├── KeyGenerationResult.java
│   │   ├── SigningResult.java
│   │   ├── VerificationResult.java
│   │   └── PublicKeyImportResult.java
│   └── service/
│       └── HsmCryptoService.java      # Main service (orchestrator)
└── src/main/resources/
    └── META-INF/spring/               # Auto-configuration registration
```

## Hash Algorithm Reference (payShield 10K)

| ID | Algorithm | PayNet RPP |
|----|-----------|------------|
| `01` | SHA-1 | |
| `02` | MD5 | |
| `04` | No Hash (raw data) | |
| `05` | SHA-224 | |
| `06` | SHA-256 |  Default |
| `07` | SHA-384 | |
| `08` | SHA-512 | |

## Scope & Limitations

- **POC-level implementation** — not production-ready
- Tested against payShield 10K firmware 2.2b on **Variant LMK port** (3DES, port 1501)
- Key Block LMK port (AES, port 1502) requires additional command fields — not yet supported
- Private key is passed **inline** in each signing request (LA/user storage not yet implemented)
- No CSR generation yet (planned: `QE` command with Bouncy Castle for TBS construction)
- Limited error handling and retry mechanisms
- No key lifecycle management (rotation, archival, expiry)
- No integration with CA or certificate lifecycle systems
- Connection pool does not handle HSM failover

## Technology Stack

- **Java**: 21
- **Spring Boot**: 3.4.1
- **Connection Pooling**: Apache Commons Pool2
- **Build**: Maven
- **HSM Protocol**: Thales payShield 10K proprietary TCP host commands

## Reference Documents

- payShield 10K Core Host Commands V1.7a (007-001515-007)
- payShield 10K Host Command Examples V1.7a (007-001443-007)


