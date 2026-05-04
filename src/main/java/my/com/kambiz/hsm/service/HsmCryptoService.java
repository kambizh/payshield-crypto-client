package my.com.kambiz.hsm.service;

import my.com.kambiz.hsm.command.*;
import my.com.kambiz.hsm.config.LmkMode;
import my.com.kambiz.hsm.config.PayShieldProperties;
import my.com.kambiz.hsm.connection.PayShieldConnectionPool;
import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * High-level service for payShield 10K HSM operations.
 *
 * Supports dual LMK modes controlled by payshield.lmk-mode property:
 *   - "variant"  → 3DES Variant LMK (port 1501)
 *   - "keyblock" → AES Key Block LMK (port 1502)
 *
 * The service automatically adjusts command construction and response parsing
 * based on the configured mode. All three core operations (generate, sign, verify)
 * are mode-aware.
 */
public class HsmCryptoService {

    private static final Logger log = LoggerFactory.getLogger(HsmCryptoService.class);

    private final PayShieldConnectionPool connectionPool;
    private final PayShieldProperties properties;

    // In-memory state for the POC (in production, this would be in a database)
    private KeyGenerationResult currentKeyPair;
    private PublicKeyImportResult currentPublicKeyImport;

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
     */
    public KeyGenerationResult generateKeyPair(int modulusBits) {
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

        this.currentKeyPair = result;
        return result;
    }

    // ===== 2. SIGNING =====

    public SigningResult signMessage(byte[] messageData) {
        return signMessage(messageData, properties.getDefaultHashId(), properties.getDefaultPadMode());
    }

    /**
     * Sign a message with specific hash and padding options.
     * Mode-aware: uses correct EW builder based on key type.
     */
    public SigningResult signMessage(byte[] messageData, String hashId, String padMode) {
        if (currentKeyPair == null) {
            throw new PayShieldException("No key pair available. Generate a key pair first.");
        }

        LmkMode mode = getLmkMode();
        log.info("=== Signing message ({} bytes) via HSM (LMK mode: {}, inline key) ===",
                messageData.length, mode);
        String header = CommandUtils.generateHeader(properties.getHeaderLength());

        byte[] ewCmd = EWCommand.buildWithInlineKeyAuto(
                header, hashId, properties.getDefaultSigId(), padMode,
                messageData,
                currentKeyPair.getPrivateKeyLmkEncrypted(),
                currentKeyPair.isKeyBlock());

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
     * Variant flow:  EO → MAC + DER → EY with MAC + DER
     * Key Block flow: EO → S-prefixed key block → EY with S-prefixed key block
     */
    public VerificationResult verifySignature(byte[] signature, byte[] messageData,
                                               byte[] publicKeyDer, String hashId, String padMode) {
        LmkMode mode = getLmkMode();
        log.info("=== Verifying signature via HSM (LMK mode: {}) ===", mode);
        String header = CommandUtils.generateHeader(properties.getHeaderLength());

        // Step 1: Import the verification public key via EO
        log.info("Step 1: Importing public key via EO command (mode: {})", mode);
        byte[] eoCmd;
        if (mode == LmkMode.KEYBLOCK) {
            // Key Block EO: needs '#' + mode of use + key version + exportability
            // For verification public key, Mode of Use = 'V' (verify)
            eoCmd = EOCommand.buildKeyBlock(header, publicKeyDer,
                    "V", properties.getKeyBlockKeyVersion(), properties.getKeyBlockExportability());
        } else {
            eoCmd = EOCommand.build(header, publicKeyDer, new byte[0]);
        }

        byte[] eoResp = connectionPool.execute(eoCmd);
        PublicKeyImportResult importResult = EOCommand.parseResponse(eoResp, properties.getHeaderLength(), mode);
        log.info("EO success: {}", mode == LmkMode.KEYBLOCK
                ? "pubKeyBlock=" + importResult.getPublicKeyBlock().length + " bytes (S-prefixed)"
                : "MAC=" + importResult.getMacHex());

        // Step 2: Verify signature via EY
        log.info("Step 2: Verifying signature via EY command (mode: {})", mode);
        byte[] eyCmd;
        if (mode == LmkMode.KEYBLOCK) {
            eyCmd = EYCommand.buildKeyBlock(
                    header, hashId, properties.getDefaultSigId(), padMode,
                    signature, messageData,
                    importResult.getPublicKeyBlock());
        } else {
            eyCmd = EYCommand.build(
                    header, hashId, properties.getDefaultSigId(), padMode,
                    signature, messageData,
                    importResult.getMac(), importResult.getPublicKeyDer(), new byte[0]);
        }

        log.debug("EY command hex: {}", CommandUtils.bytesToHex(eyCmd));
        byte[] eyResp = connectionPool.execute(eyCmd);

        return EYCommand.parseResponse(eyResp, properties.getHeaderLength());
    }

    // ===== 4. CSR GENERATION (Key Block LMK only) =====

    /**
     * Generate a Certificate Signing Request (CSR) via the native QE command.
     * Requires Key Block LMK mode (port 1502) — the QE command only accepts
     * 'S'-prefixed Key Block private keys.
     *
     * The HSM internally builds the PKCS#10 envelope and signs it — the private
     * key never leaves the HSM boundary.
     *
     * @param commonName  CN for the CSR subject
     * @param organization O
     * @param orgUnit     OU
     * @param locality    L
     * @param state       ST
     * @param country     C (2-char ISO code)
     * @param pemOutput   true=PEM format, false=Hex DER format
     * @return CSR data (PEM or Hex DER)
     */
    public CsrGenerationResult generateCsr(String commonName, String organization,
                                            String orgUnit, String locality,
                                            String state, String country,
                                            boolean pemOutput) {
        if (currentKeyPair == null) {
            throw new PayShieldException("No key pair available. Generate a key pair first.");
        }
        if (!currentKeyPair.isKeyBlock()) {
            throw new PayShieldException("CSR generation via QE requires Key Block LMK mode. " +
                    "Current key pair was generated in Variant LMK mode.");
        }

        LmkMode mode = getLmkMode();
        log.info("=== Generating CSR via HSM QE command (LMK mode: {}) ===", mode);
        log.info("Subject: CN={}, O={}, OU={}, L={}, ST={}, C={}",
                commonName, organization, orgUnit, locality, state, country);

        String header = CommandUtils.generateHeader(properties.getHeaderLength());

        byte[] qeCmd;
        if (pemOutput) {
            qeCmd = QECommand.buildPem(header,
                    currentKeyPair.getPublicKeyDer(),
                    currentKeyPair.getPrivateKeyLmkEncrypted(),
                    commonName, organization, orgUnit, locality, state, country);
        } else {
            qeCmd = QECommand.buildDer(header,
                    currentKeyPair.getPublicKeyDer(),
                    currentKeyPair.getPrivateKeyLmkEncrypted(),
                    commonName, organization, orgUnit, locality, state, country);
        }

        log.debug("QE command length: {} bytes", qeCmd.length);
        byte[] qeResp = connectionPool.execute(qeCmd);

        CsrGenerationResult result = QECommand.parseResponse(qeResp, properties.getHeaderLength());
        log.info("QE success: CSR generated, {} chars, format={}",
                result.getCsrLength(), pemOutput ? "PEM" : "HexDER");

        return result;
    }

    /**
     * Generate CSR with PEM output using default hash (SHA-256) and padding (PKCS#1 v1.5).
     */
    public CsrGenerationResult generateCsrPem(String commonName, String organization,
                                               String orgUnit, String locality,
                                               String state, String country) {
        return generateCsr(commonName, organization, orgUnit, locality, state, country, true);
    }

    // ===== UTILITY =====

    /**
     * Import a public key via EO (mode-aware).
     */
    public PublicKeyImportResult importPublicKey(byte[] publicKeyDer) {
        LmkMode mode = getLmkMode();
        String header = CommandUtils.generateHeader(properties.getHeaderLength());

        byte[] eoCmd;
        if (mode == LmkMode.KEYBLOCK) {
            eoCmd = EOCommand.buildKeyBlock(header, publicKeyDer,
                    "N", properties.getKeyBlockKeyVersion(), properties.getKeyBlockExportability());
        } else {
            eoCmd = EOCommand.build(header, publicKeyDer, new byte[0]);
        }

        byte[] eoResp = connectionPool.execute(eoCmd);
        return EOCommand.parseResponse(eoResp, properties.getHeaderLength(), mode);
    }

    public KeyGenerationResult getCurrentKeyPair() { return currentKeyPair; }
    public PublicKeyImportResult getCurrentPublicKeyImport() { return currentPublicKeyImport; }
    public String getPoolStats() { return connectionPool.getPoolStats(); }

    /**
     * Execute a raw command against the HSM.
     */
    public byte[] executeRaw(byte[] command) {
        return connectionPool.execute(command);
    }
}