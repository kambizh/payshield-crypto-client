# payshield-crypto-client

A Spring Boot auto-configuration library for integrating with the Thales payShield 10K HSM
over native TCP host commands. It abstracts low-level command framing and provides a
stateless Java API for RSA key generation, digital signing, signature verification,
CSR generation, and diagnostics.

RSA private keys never leave the HSM boundary in cleartext. All cryptographic operations
are performed inside the tamper-resistant HSM hardware.

---

## Supported HSM Commands

| Command | Response | Operation | Notes |
|---------|----------|-----------|-------|
| `EI` | `EJ` | Generate RSA Key Pair | Variant + Key Block |
| `EW` | `EX` | Generate Digital Signature | Inline private key (flag 99) |
| `EO` | `EP` | Import Public Key | MAC+DER (Variant) or `S`-prefixed key block (Key Block) |
| `EY` | `EZ` | Verify Digital Signature | Mode-aware |
| `QE` | `QF` | Generate PKCS#10 CSR | Key Block LMK only |
| `NC` | `ND` | Perform Diagnostics | LMK check value, firmware number |
| `NO` | `NP` | HSM Status | Buffer size, TCP sockets, firmware |
| `LA` | `LB` | Load to User Storage | Planned |

---

## LMK Modes

The library supports two LMK architectures, selectable via `payshield.lmk-mode`:

| Mode | Property value | Port | Private key format |
|------|----------------|------|--------------------|
| **Key Block LMK** (AES, TR-31) | `keyblock` *(default)* | 1502 | `S`-prefixed key block; EJ length field = `FFFF` |
| **Variant LMK** (3DES, legacy) | `variant` | 1501 | Raw LMK-encrypted blob; EJ length field = decimal byte count |

Key Block is the default and recommended mode. Variant is retained for compatibility only.

---

## Architecture

```
┌──────────────────────────────────────────┐
│           Caller Application             │
│        (Spring Boot service / app)       │
└───────────────────┬──────────────────────┘
                    │ @Autowired HsmCryptoService
┌───────────────────▼──────────────────────┐
│         payshield-crypto-client          │
│            (JAR dependency)              │
│                                          │
│  ┌──────────────────┐  ┌──────────────┐  │
│  │ HsmCryptoService │  │   Command    │  │
│  │  (stateless API) │  │   Builders   │  │
│  └────────┬─────────┘  │ EI/EW/EO/EY  │  │
│           │            │  QE/NC/NO    │  │
│  ┌────────▼──────────────────────────┐│  │
│  │  PayShieldConnectionPool          ││  │
│  │  (Apache Commons Pool2)           ││  │
│  │   └─ PayShieldConnection          ││  │
│  │      (TCP + 2-byte length prefix) ││  │
│  └───────────────────────────────────┘│  │
└───────────────────┬──────────────────────┘
                    │ TCP
           ┌────────▼────────┐
           │ payShield 10K   │
           │  port 1502      │
           │  (Key Block)    │
           └─────────────────┘
```

The library handles:
- **Connection pooling** — Apache Commons Pool2, configurable pool size
- **LMK mode selection** — dual-port, command builders and parsers adapt automatically
- **Protocol framing** — 2-byte big-endian length prefix, configurable header
- **Response parsing** — DER public keys, key blobs, signatures, error codes
- **Spring Boot auto-configuration** — zero-boilerplate drop-in via `@ConfigurationProperties`

---

## Key Flows

### Key Block LMK (port 1502) — default

1. **EI** → HSM generates RSA pair; returns DER public key + `S`-prefixed private key block (`FFFF` length sentinel in EJ).
2. **EW** → Caller passes the `S`-prefixed blob back; HSM unwraps under LMK, signs, returns signature.
3. **EO + EY** → EO imports a DER public key and returns an `S`-prefixed public key block; EY verifies using that block + message.
4. **QE** → Caller passes DER public key + `S`-prefixed private key block; HSM builds and self-signs the PKCS#10 CSR internally.

### Variant LMK (port 1501)

1. **EI** → Returns DER public key + raw LMK-encrypted private blob (decimal length in EJ).
2. **EW** → Caller passes the raw blob back; HSM signs, returns signature.
3. **EO + EY** → EO returns MAC + DER public key; EY verifies using MAC + DER + message.

> The HSM does not retain key pairs between commands. The caller stores the private key
> blob returned by `generateKeyPair()` and supplies it on each `signMessage()` or
> `generateCsr()` call.

---

## Configuration

Minimum required — only `payshield.host` is mandatory:

```yaml
payshield:
  host: 192.168.1.100
```

Full reference:

```yaml
payshield:
  # Connection
  host: 192.168.1.100          # HSM IP (required)
  port: 1501                   # Variant LMK port (default: 1501)
  port-key-block: 1502         # Key Block LMK port (default: 1502)
  lmk-mode: keyblock           # "keyblock" (default) or "variant"
  connect-timeout-ms: 5000
  read-timeout-ms: 10000
  length-prefix-enabled: true
  header-length: 4             # 0, 2, or 4 — must match HSM config

  # Connection pool
  pool-max-total: 5
  pool-max-idle: 3
  pool-min-idle: 1

  # Cryptographic defaults
  default-modulus-length: 2048
  default-hash-id: "06"        # SHA-256
  default-sig-id: "01"         # RSA
  default-pad-mode: "01"       # PKCS#1 v1.5

  # Key Block attributes (keyblock mode only)
  key-block-mode-of-use: S     # S=Sign, D=Decrypt, N=No restriction
  key-block-key-version: "00"
  key-block-exportability: N   # N=Non-exportable, S=Exportable
```

---

## Usage

Auto-wired via Spring Boot — no `@Bean` declarations needed:

```java
@Autowired
private HsmCryptoService hsmService;
```

### Generate a key pair

```java
KeyGenerationResult keyPair = hsmService.generateKeyPair(2048);

// Store these — the library is stateless and will not retain them
byte[] publicKeyDer   = keyPair.getPublicKeyDer();
byte[] privateKeyBlob = keyPair.getPrivateKeyLmkEncrypted();
boolean isKeyBlock    = keyPair.isKeyBlock();
```

### Sign a message

```java
byte[] message = "data to sign".getBytes(StandardCharsets.UTF_8);

SigningResult signing = hsmService.signMessage(message, privateKeyBlob, isKeyBlock);
byte[] signature = signing.getSignature();
```

### Verify a signature

```java
VerificationResult result = hsmService.verifySignature(signature, message, publicKeyDer);

if (result.isValid()) {
    // signature is valid
} else {
    log.warn("Verification failed: {}", result.getErrorDescription());
}
```

### Generate a CSR (Key Block mode only)

```java
CsrGenerationResult csr = hsmService.generateCsrPem(
    publicKeyDer,
    privateKeyBlob,
    "my-service.example.com",  // CN
    "My Organisation",         // O
    "Engineering",             // OU
    "Kuala Lumpur",            // L
    "Wilayah Persekutuan",     // ST
    "MY"                       // C — 2-char ISO 3166-1
);

String pem = csr.getFormattedPem();
```

### Diagnostics / health check

```java
String header = "0000"; // match payshield.header-length
int headerLen = 4;

byte[] resp = hsmService.executeRaw(DiagnosticCommands.buildNC(header));
Map<String, String> diag = DiagnosticCommands.parseNCResponse(resp, headerLen);
// diag: status, firmwareNumber, lmkCheckValue
```

---

## Project Structure

```
payshield-crypto-client/
├── src/main/java/my/com/kambiz/hsm/
│   ├── command/
│   │   ├── CommandUtils.java          # Wire format utilities
│   │   ├── EICommand.java             # Generate RSA Key Pair
│   │   ├── EWCommand.java             # Generate Digital Signature
│   │   ├── EOCommand.java             # Import Public Key
│   │   ├── EYCommand.java             # Verify Digital Signature
│   │   ├── QECommand.java             # Generate PKCS#10 CSR
│   │   ├── LACommand.java             # Load to User Storage (planned)
│   │   └── DiagnosticCommands.java    # NC + NO diagnostics
│   ├── config/
│   │   ├── LmkMode.java
│   │   ├── PayShieldProperties.java
│   │   └── PayShieldAutoConfiguration.java
│   ├── connection/
│   │   ├── PayShieldConnection.java
│   │   ├── PayShieldConnectionFactory.java
│   │   └── PayShieldConnectionPool.java
│   ├── exception/
│   │   └── PayShieldException.java
│   ├── model/
│   │   ├── KeyGenerationResult.java
│   │   ├── SigningResult.java
│   │   ├── VerificationResult.java
│   │   ├── PublicKeyImportResult.java
│   │   └── CsrGenerationResult.java
│   └── service/
│       └── HsmCryptoService.java
└── src/main/resources/
    └── META-INF/spring/               # Auto-configuration registration
```

---

## Hash & Padding Reference

### Hash algorithm IDs

| ID | Algorithm |
|----|-----------|
| `01` | SHA-1 |
| `02` | MD5 |
| `04` | No hash (raw data) |
| `05` | SHA-224 |
| `06` | SHA-256 *(default)* |
| `07` | SHA-384 |
| `08` | SHA-512 |

### Padding mode IDs

| ID | Mode |
|----|------|
| `01` | PKCS#1 v1.5 *(default)* |
| `02` | ANSI X9.31 |
| `03` | ISO 9796 |
| `04` | PSS (RSASSA-PSS) |

---

## Known Limitations

- `LA` / HSM user storage not yet implemented — private keys are passed inline on every call
- Connection pool does not handle HSM failover or multi-HSM load balancing
- No key lifecycle management (rotation, archival, expiry)
- CSR generation (`QE`) requires Key Block LMK mode

---

## Tested Environment

- **HSM**: Thales payShield 10K
- **Firmware**: 2200-1011 (version 2.2b)
- **Ports**: 1501 (Variant LMK), 1502 (Key Block LMK)
- **Key size**: RSA-2048
- **Hash**: SHA-256 (`06`)
- **Padding**: PKCS#1 v1.5 (`01`)

Validate port assignments and LMK profiles against your site's HSM provisioning sheet.

---

## Technology Stack

- **Java** 21
- **Spring Boot** 3.4.1
- **Connection pooling**: Apache Commons Pool2
- **Build**: Maven

---

## Reference Documents

- payShield 10K Core Host Commands V1.7a (007-001515-007)
- payShield 10K Host Command Examples V1.7a (007-001443-007)
