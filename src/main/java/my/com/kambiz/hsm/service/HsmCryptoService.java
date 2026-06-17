package my.com.kambiz.hsm.service;

import my.com.kambiz.hsm.command.*;
import my.com.kambiz.hsm.config.LmkMode;
import my.com.kambiz.hsm.crypto.*;
import my.com.kambiz.hsm.config.PayShieldProperties;
import my.com.kambiz.hsm.connection.PayShieldConnectionPool;
import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Stateless service for payShield 10K HSM operations.
 *
 * Supports dual LMK modes controlled by payshield.lmk-mode property:
 *   - "variant"  → 3DES Variant LMK (port 1501)
 *   - "keyblock" → AES Key Block LMK (port 1502)
 *
 * This service holds no state between calls. The caller is responsible for
 * storing and passing back any key material returned by previous operations.
 */
public class HsmCryptoService {

    private static final Logger log = LoggerFactory.getLogger(HsmCryptoService.class);

    private final PayShieldConnectionPool connectionPool;
    private final PayShieldProperties properties;

    public HsmCryptoService(PayShieldConnectionPool connectionPool, PayShieldProperties properties) {
        this.connectionPool = connectionPool;
        this.properties = properties;
    }

    /**
     * Returns the active LMK mode.
     */
    public LmkMode getLmkMode() {
        return properties.getResolvedLmkMode();
    }

    // ===== 1. KEY GENERATION =====

    /**
     * Generate an RSA key pair inside the HSM.
     * Mode-aware: constructs Variant or Key Block EI command based on config.
     *
     * @param modulusBits RSA key size — must be 1024, 2048, or 4096
     */
    public KeyGenerationResult generateKeyPair(int modulusBits) {
        if (modulusBits != 1024 && modulusBits != 2048 && modulusBits != 4096) {
            throw new IllegalArgumentException(
                    "modulusBits must be 1024, 2048, or 4096; got: " + modulusBits);
        }
        LmkMode mode = getLmkMode();
        log.info("=== Generating RSA-{} key pair via HSM (LMK mode: {}) ===", modulusBits, mode);
        String header = CommandUtils.generateHeader(properties.getHeaderLength());

        byte[] eiCmd;
        if (mode == LmkMode.KEYBLOCK) {
            eiCmd = EICommand.buildKeyBlock(header, 0, modulusBits, "01",
                    properties.getKeyBlockKeyVersion());
            log.info("EI command (KEY BLOCK): keyType=0, bits={}, version={}",
                    modulusBits, properties.getKeyBlockKeyVersion());
        } else {
            eiCmd = EICommand.build(header, 0, modulusBits, "01");
            log.info("EI command (VARIANT): keyType=0, bits={}", modulusBits);
        }

        log.debug("EI command hex: {}", CommandUtils.bytesToHex(eiCmd));
        byte[] eiResp = connectionPool.execute(eiCmd);

        // Parse response — auto-detects Variant vs Key Block from FFFF length field
        KeyGenerationResult result = EICommand.parseResponse(eiResp, properties.getHeaderLength(), modulusBits);

        log.info("EI success: publicKey={} bytes, privateKey={} bytes, scheme={}",
                result.getPublicKeyDer().length,
                result.getPrivateKeyLmkEncrypted().length,
                result.getLmkScheme());

        return result;
    }

    // ===== 2. SIGNING =====

    /**
     * Sign a message using the default hash and padding from configuration.
     *
     * @param messageData      data to sign
     * @param privateKeyBlob   LMK-encrypted private key blob returned by generateKeyPair()
     */
    public SigningResult signMessage(byte[] messageData, byte[] privateKeyBlob) {
        return signMessage(messageData, privateKeyBlob,
                properties.getDefaultHashId(), properties.getDefaultPadMode());
    }

    /**
     * Sign a message with explicit hash and padding options.
     *
     * @param messageData      data to sign
     * @param privateKeyBlob   LMK-encrypted private key blob returned by generateKeyPair()
     * @param hashId           hash algorithm ID (e.g. "06" = SHA-256)
     * @param padMode          padding mode ID (e.g. "01" = PKCS#1 v1.5)
     */
    public SigningResult signMessage(byte[] messageData, byte[] privateKeyBlob,
                                     String hashId, String padMode) {
        requireNonEmpty(messageData, "messageData");
        requireNonEmpty(privateKeyBlob, "privateKeyBlob");
        LmkMode mode = getLmkMode();
        boolean isKeyBlock = mode == LmkMode.KEYBLOCK;
        log.info("=== Signing message ({} bytes) via HSM (LMK mode: {}, inline key) ===",
                messageData.length, mode);
        String header = CommandUtils.generateHeader(properties.getHeaderLength());

        byte[] ewCmd = EWCommand.buildWithInlineKeyAuto(
                header, hashId, properties.getDefaultSigId(), padMode,
                messageData, privateKeyBlob, isKeyBlock);

        log.debug("EW command length: {} bytes", ewCmd.length);
        byte[] ewResp = connectionPool.execute(ewCmd);

        return EWCommand.parseResponse(ewResp, properties.getHeaderLength(), hashId, padMode);
    }

    // ===== 3. VERIFICATION =====

    public VerificationResult verifySignature(byte[] signature, byte[] messageData, byte[] publicKeyDer) {
        return verifySignature(signature, messageData, publicKeyDer,
                properties.getDefaultHashId(), properties.getDefaultPadMode());
    }

    /**
     * Verify a signature with specific hash and padding options.
     * Mode-aware: uses correct EO/EY builders and parsers.
     *
     * Runs the full two-command flow on every call:
     *   Variant flow:   EO → MAC + DER → EY with MAC + DER
     *   Key Block flow: EO → S-prefixed key block → EY with S-prefixed key block
     *
     * For high-volume verification against a stable public key (e.g. PayNet's), prefer
     * importing once via {@link #importPublicKeyForVerification(byte[])} and then calling
     * {@link #verifySignature(byte[], byte[], PublicKeyImportResult, String, String)} per
     * message — that sends only the EY command and skips the repeated EO round-trip.
     */
    public VerificationResult verifySignature(byte[] signature, byte[] messageData,
                                               byte[] publicKeyDer, String hashId, String padMode) {
        requireNonEmpty(signature, "signature");
        requireNonEmpty(messageData, "messageData");
        requireNonEmpty(publicKeyDer, "publicKeyDer");
        log.info("=== Verifying signature via HSM, full EO + EY (LMK mode: {}) ===", getLmkMode());

        // Step 1: Import the verification public key via EO
        PublicKeyImportResult importResult = importPublicKeyForVerification(publicKeyDer);

        // Step 2: Verify signature via EY using the freshly imported key
        return verifySignature(signature, messageData, importResult, hashId, padMode);
    }

    /**
     * Import a public key via EO specifically for signature verification
     * (Key Block Mode of Use = 'V').
     *
     * Do this ONCE per public key and cache the returned {@link PublicKeyImportResult}.
     * You can then call
     * {@link #verifySignature(byte[], byte[], PublicKeyImportResult, String, String)}
     * repeatedly, which sends only the EY command — halving HSM round-trips per verify.
     *
     * The cached result stays valid as long as the HSM's LMK is unchanged. If the LMK is
     * reloaded/replaced, re-import: the old MAC (Variant) or key block (Key Block) will no
     * longer validate and EY would fail with a MAC/key-block error.
     *
     * NOTE: this differs from {@link #importPublicKey(byte[])}, which imports with
     * Mode of Use = 'N' (no restriction). For verification reuse, 'V' is the correct usage.
     *
     * @param publicKeyDer DER-encoded SubjectPublicKeyInfo (X.509) public key
     * @return import result to cache and reuse across EY verifications
     */
    public PublicKeyImportResult importPublicKeyForVerification(byte[] publicKeyDer) {
        requireNonEmpty(publicKeyDer, "publicKeyDer");
        LmkMode mode = getLmkMode();
        log.info("Importing public key via EO for verification (mode: {})", mode);
        PublicKeyImportResult result = executeEoImport(publicKeyDer, "V");
        log.info("EO success: {}", mode == LmkMode.KEYBLOCK
                ? "pubKeyBlock=" + result.getPublicKeyBlock().length + " bytes (S-prefixed)"
                : "MAC=" + result.getMacHex());
        return result;
    }

    /**
     * Verify a signature using a PREVIOUSLY IMPORTED public key (EY command only).
     *
     * Skips the EO step by reusing a {@link PublicKeyImportResult} obtained once from
     * {@link #importPublicKeyForVerification(byte[])}. Ideal for high-volume verification
     * against a stable public key (e.g. PayNet's) — one EY round-trip per message instead
     * of EO + EY.
     *
     * @param signature   raw signature bytes
     * @param messageData original signed message
     * @param importedKey cached EO result (MAC + DER for Variant, or S-prefixed key block)
     * @param hashId      hash algorithm ID (e.g. "06" = SHA-256)
     * @param padMode     padding mode ID ("01" = PKCS#1 v1.5)
     */
    public VerificationResult verifySignature(byte[] signature, byte[] messageData,
                                              PublicKeyImportResult importedKey,
                                              String hashId, String padMode) {
        requireNonEmpty(signature, "signature");
        requireNonEmpty(messageData, "messageData");
        if (importedKey == null) {
            throw new IllegalArgumentException("importedKey must not be null");
        }
        LmkMode mode = getLmkMode();
        log.info("=== Verifying signature via HSM, EY only / cached EO (LMK mode: {}) ===", mode);
        String header = CommandUtils.generateHeader(properties.getHeaderLength());

        byte[] eyCmd;
        if (mode == LmkMode.KEYBLOCK) {
            eyCmd = EYCommand.buildKeyBlock(
                    header, hashId, properties.getDefaultSigId(), padMode,
                    signature, messageData,
                    importedKey.getPublicKeyBlock());
        } else {
            eyCmd = EYCommand.build(
                    header, hashId, properties.getDefaultSigId(), padMode,
                    signature, messageData,
                    importedKey.getMac(), importedKey.getPublicKeyDer(), new byte[0]);
        }

        log.debug("EY command hex: {}", CommandUtils.bytesToHex(eyCmd));
        byte[] eyResp = connectionPool.execute(eyCmd);

        return EYCommand.parseResponse(eyResp, properties.getHeaderLength());
    }

    // ===== 3b. SOFTWARE (OFF-HSM) VERIFICATION =====

    /**
     * Verify a signature entirely in software, WITHOUT contacting the HSM.
     *
     * Verification only needs the signer's public key, which is public material.
     * No LMK, no private key, and no HSM round-trip are involved — this runs purely
     * on the JVM. Use this for high-volume inbound verification (e.g. checking
     * PayNet-signed messages) where you do not want to spend an HSM connection per message.
     *
     * Uses the configured default hash and pad mode.
     * Key type: RSA only. Supported hash IDs: 01/05/06/07/08. Pad modes: 01/04.
     *
     * @param signature    raw signature bytes
     * @param messageData  original signed message
     * @param publicKeyDer DER-encoded SubjectPublicKeyInfo (X.509) — RSA public key
     */
    public VerificationResult verifySignatureOffHsm(byte[] signature, byte[] messageData,
                                                    byte[] publicKeyDer) {
        return verifySignatureOffHsm(signature, messageData, publicKeyDer,
                properties.getDefaultHashId(), properties.getDefaultPadMode());
    }

    /**
     * Verify a signature in software with explicit hash and padding options.
     * Does not contact the HSM.
     *
     * Key type: RSA only (EC keys throw {@link IllegalArgumentException}).
     * Supported hash IDs: 01 (SHA-1), 05 (SHA-224), 06 (SHA-256), 07 (SHA-384), 08 (SHA-512).
     * Supported pad modes: 01 (PKCS#1 v1.5), 04 (PSS, salt length = digest length).
     * A structurally malformed signature returns {@code valid=false} rather than throwing.
     *
     * @param signature    raw signature bytes
     * @param messageData  original signed message
     * @param publicKeyDer DER-encoded SubjectPublicKeyInfo (X.509) — RSA public key
     * @param hashId       payShield hash algorithm ID (e.g. "06" = SHA-256)
     * @param padMode      payShield padding mode ID ("01" = PKCS#1 v1.5, "04" = PSS)
     */
    public VerificationResult verifySignatureOffHsm(byte[] signature, byte[] messageData,
                                                    byte[] publicKeyDer, String hashId, String padMode) {
        requireNonEmpty(signature, "signature");
        requireNonEmpty(messageData, "messageData");
        requireNonEmpty(publicKeyDer, "publicKeyDer");
        log.info("=== Verifying signature in SOFTWARE (no HSM call), hash={}, pad={} ===", hashId, padMode);
        VerificationResult result = SoftwareSignatureVerifier.verify(
                signature, messageData, publicKeyDer, hashId, padMode);
        log.info("Software verification result: valid={}, errorCode={}", result.isValid(), result.getErrorCode());
        return result;
    }

    // ===== 4. CSR GENERATION =====

    /**
     * Generate a Certificate Signing Request (CSR). Mode-aware:
     *
     *   Key Block LMK → QE command: the HSM builds and signs the PKCS#10 envelope internally.
     *                               Requires an S-prefixed TR-31 private key block.
     *
     *   Variant LMK   → Software:   TbsCertificationRequest is built in Java, then signed
     *                               by the HSM via EW (SHA-256 + PKCS#1 v1.5). The PKCS#10
     *                               structure is assembled in Java. The private key never
     *                               leaves the HSM in either path.
     *
     * @param publicKeyDer    DER-encoded public key from generateKeyPair()
     * @param privateKeyBlob  LMK-encrypted private key blob from generateKeyPair()
     *                        (S-prefixed Key Block for keyblock mode, raw blob for variant mode)
     * @param commonName      CN for the CSR subject
     * @param organization    O
     * @param orgUnit         OU
     * @param locality        L
     * @param state           ST
     * @param country         C (2-char ISO code)
     * @param pemOutput       true=PEM format, false=Hex DER format
     * @return CSR data (PEM or Hex DER)
     */
    public CsrGenerationResult generateCsr(byte[] publicKeyDer, byte[] privateKeyBlob,
                                            String commonName, String organization,
                                            String orgUnit, String locality,
                                            String state, String country,
                                            boolean pemOutput) {
        requireNonEmpty(publicKeyDer, "publicKeyDer");
        requireNonEmpty(privateKeyBlob, "privateKeyBlob");
        requireNonBlank(commonName, "commonName");
        requireNonBlank(organization, "organization");
        requireNonBlank(orgUnit, "orgUnit");
        requireNonBlank(locality, "locality");
        requireNonBlank(state, "state");
        if (country == null || country.length() != 2) {
            throw new IllegalArgumentException(
                    "country must be a 2-character ISO 3166-1 code (e.g. \"MY\"); got: " + country);
        }

        LmkMode mode = getLmkMode();
        log.info("=== Generating CSR (LMK mode: {}, format: {}) ===",
                mode, pemOutput ? "PEM" : "HexDER");
        log.info("Subject: CN={}, O={}, OU={}, L={}, ST={}, C={}",
                commonName, organization, orgUnit, locality, state, country);

        if (mode == LmkMode.KEYBLOCK) {
            return generateCsrKeyBlock(publicKeyDer, privateKeyBlob,
                    commonName, organization, orgUnit, locality, state, country, pemOutput);
        } else {
            return generateCsrVariant(publicKeyDer, privateKeyBlob,
                    commonName, organization, orgUnit, locality, state, country, pemOutput);
        }
    }

    /**
     * Key Block path: delegate to QE command.
     * QE handles signing inside the HSM; the private key blob must be S-prefixed.
     */
    private CsrGenerationResult generateCsrKeyBlock(byte[] publicKeyDer, byte[] privateKeyBlob,
                                                      String cn, String o, String ou,
                                                      String l, String st, String c,
                                                      boolean pemOutput) {
        log.info("CSR path: QE command (Key Block LMK)");
        String header = CommandUtils.generateHeader(properties.getHeaderLength());

        byte[] qeCmd = pemOutput
                ? QECommand.buildPem(header, publicKeyDer, privateKeyBlob, cn, o, ou, l, st, c)
                : QECommand.buildDer(header, publicKeyDer, privateKeyBlob, cn, o, ou, l, st, c);

        log.debug("QE command length: {} bytes", qeCmd.length);
        byte[] qeResp = connectionPool.execute(qeCmd);

        CsrGenerationResult result = QECommand.parseResponse(qeResp, properties.getHeaderLength());
        log.info("QE success: CSR {} chars, format={}", result.getCsrLength(), pemOutput ? "PEM" : "HexDER");
        return result;
    }

    /**
     * Variant path: build TBS in software, sign with EW, assemble PKCS#10 in software.
     * Uses SHA-256 + PKCS#1 v1.5 (sha256WithRSAEncryption) — same as QE default.
     */
    private CsrGenerationResult generateCsrVariant(byte[] publicKeyDer, byte[] privateKeyBlob,
                                                     String cn, String o, String ou,
                                                     String l, String st, String c,
                                                     boolean pemOutput) {
        log.info("CSR path: software build + EW signing (Variant LMK)");

        // 1. Build Subject DER and TbsCertificationRequest
        byte[] subjectDer = SoftwareCsrBuilder.buildSubjectDer(cn, o, ou, l, st, c);
        byte[] tbsDer = SoftwareCsrBuilder.buildTbs(subjectDer, publicKeyDer);
        log.debug("TbsCertificationRequest: {} bytes", tbsDer.length);

        // 2. Sign TBS via HSM EW command (SHA-256 + PKCS#1 v1.5)
        SigningResult sigResult = signMessage(tbsDer, privateKeyBlob, "06", "01");
        byte[] signature = sigResult.getSignature();
        log.debug("EW signature: {} bytes", signature.length);

        // 3. Assemble the full PKCS#10 CertificationRequest DER
        byte[] csrDer = SoftwareCsrBuilder.buildCsr(tbsDer, signature);

        String csrData = pemOutput
                ? SoftwareCsrBuilder.toPem(csrDer)
                : SoftwareCsrBuilder.toHex(csrDer);

        log.info("Software CSR success: {} bytes DER, {} chars output, format={}",
                csrDer.length, csrData.length(), pemOutput ? "PEM" : "HexDER");
        return new CsrGenerationResult(csrData, csrData.length());
    }

    /**
     * Generate CSR in PEM format. Mode-aware — works for both Variant and Key Block.
     *
     * @param publicKeyDer   DER-encoded public key from generateKeyPair()
     * @param privateKeyBlob LMK-encrypted private key blob from generateKeyPair()
     */
    public CsrGenerationResult generateCsrPem(byte[] publicKeyDer, byte[] privateKeyBlob,
                                               String commonName, String organization,
                                               String orgUnit, String locality,
                                               String state, String country) {
        return generateCsr(publicKeyDer, privateKeyBlob,
                commonName, organization, orgUnit, locality, state, country, true);
    }

    // ===== UTILITY =====

    /**
     * Import a public key via EO (mode-aware), with Mode of Use = 'N' (no restriction).
     * For verification reuse, prefer {@link #importPublicKeyForVerification(byte[])} which
     * imports with Mode of Use = 'V'.
     */
    public PublicKeyImportResult importPublicKey(byte[] publicKeyDer) {
        requireNonEmpty(publicKeyDer, "publicKeyDer");
        return executeEoImport(publicKeyDer, "N");
    }

    public String getPoolStats() { return connectionPool.getPoolStats(); }

    public java.util.Map<String, Object> getDetailedPoolStats() { return connectionPool.getDetailedPoolStats(); }

    /**
     * Send a raw command byte array to the HSM and return the raw response.
     * Intended for diagnostics (NC, NO) only — use the typed methods for all
     * cryptographic operations.
     */
    public byte[] executeRaw(byte[] command) {
        requireNonEmpty(command, "command");
        return connectionPool.execute(command);
    }

    // ===== PRIVATE HELPERS =====

    private PublicKeyImportResult executeEoImport(byte[] publicKeyDer, String keyBlockModeOfUse) {
        LmkMode mode = getLmkMode();
        String header = CommandUtils.generateHeader(properties.getHeaderLength());
        byte[] eoCmd = (mode == LmkMode.KEYBLOCK)
                ? EOCommand.buildKeyBlock(header, publicKeyDer,
                        keyBlockModeOfUse, properties.getKeyBlockKeyVersion(), properties.getKeyBlockExportability())
                : EOCommand.build(header, publicKeyDer, new byte[0]);
        byte[] eoResp = connectionPool.execute(eoCmd);
        return EOCommand.parseResponse(eoResp, properties.getHeaderLength(), mode);
    }

    private static void requireNonEmpty(byte[] value, String name) {
        if (value == null || value.length == 0) {
            throw new IllegalArgumentException(name + " must not be null or empty");
        }
    }

    private static void requireNonBlank(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be null or blank");
        }
    }
}