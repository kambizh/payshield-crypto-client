package my.com.kambiz.hsm.service;

import my.com.kambiz.hsm.command.*;
import my.com.kambiz.hsm.config.PayShieldProperties;
import my.com.kambiz.hsm.connection.PayShieldConnectionPool;
import my.com.kambiz.hsm.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * High-level service for payShield 10K HSM operations.
 * 
 * Provides three main operations for the POC:
 * 1. Generate RSA key pair (EI) + store private key (LA)
 * 2. Sign a message (EW) using the stored private key
 * 3. Verify a signature (EY) using a public key
 * 
 * Also supports importing a public key (EO) to get the MAC needed for verification.
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

    // ===== 1. KEY GENERATION =====

    /**
     * Generate an RSA key pair inside the HSM and store the private key in user storage.
     * 
     * Flow:
     *   1. EI command (key type 0, RPP-style) → generates key pair, returns public key (DER) + private key (LMK-encrypted)
     *   2. LA command → stores the LMK-encrypted private key at user storage index (e.g., 000)
     *   3. EO command → imports the public key to get the MAC for later verification
     */
    public KeyGenerationResult generateKeyPair(int modulusBits) {
        log.info("=== Generating RSA-{} key pair via HSM ===", modulusBits);
        String header = CommandUtils.generateHeader(properties.getHeaderLength());

        // Step 1: EI - Generate RSA Key Pair
        log.info("Step 1: Sending EI command (Generate RSA Key Pair, {} bits)", modulusBits);
        byte[] eiCmd = EICommand.build(header, 1, modulusBits, "01");
        log.debug("EI command hex: {}", CommandUtils.bytesToHex(eiCmd));

        byte[] eiResp = connectionPool.execute(eiCmd);
        KeyGenerationResult result = EICommand.parseResponse(eiResp, properties.getHeaderLength(), modulusBits);
        log.info("EI success: publicKey={} bytes, privateKey={} bytes (LMK-encrypted)",
                result.getPublicKeyDer().length, result.getPrivateKeyLmkEncrypted().length);

        // Step 2: LA - Store private key in HSM user storage
        String storageIndex = properties.getPrivateKeyStorageIndex();
        log.info("Step 2: Sending LA command (Store private key at index {})", storageIndex);
        byte[] laCmd = LACommand.build(header, storageIndex, result.getPrivateKeyLmkEncrypted());
        byte[] laResp = connectionPool.execute(laCmd);
        LACommand.verifyResponse(laResp, properties.getHeaderLength());
        log.info("LA success: private key stored at user storage index {}", storageIndex);

        // Step 3: EO - Import the public key to get MAC for verification
        log.info("Step 3: Sending EO command (Import public key for MAC)");
        byte[] eoCmd = EOCommand.build(header, result.getPublicKeyDer(), new byte[0]);
        byte[] eoResp = connectionPool.execute(eoCmd);
        PublicKeyImportResult importResult = EOCommand.parseResponse(eoResp, properties.getHeaderLength());
        log.info("EO success: MAC={}", importResult.getMacHex());

        // Store in memory for subsequent operations
        this.currentKeyPair = result;
        this.currentPublicKeyImport = importResult;

        return result;
    }

    // ===== 2. SIGNING =====

    /**
     * Sign a message using the RSA private key stored in HSM user storage.
     * Uses the EW command with key flag 91 (variant LMK, user storage reference).
     */
    public SigningResult signMessage(byte[] messageData) {
        return signMessage(messageData, properties.getDefaultHashId(), properties.getDefaultPadMode());
    }

    /**
     * Sign a message with specific hash and padding options.
     */
    public SigningResult signMessage(byte[] messageData, String hashId, String padMode) {
        log.info("=== Signing message ({} bytes) via HSM ===", messageData.length);
        String header = CommandUtils.generateHeader(properties.getHeaderLength());
        String storageIndex = properties.getPrivateKeyStorageIndex();

        byte[] ewCmd = EWCommand.buildWithUserStorage(
                header, hashId, properties.getDefaultSigId(), padMode,
                messageData, storageIndex);

        log.debug("EW command hex: {}", CommandUtils.bytesToHex(ewCmd));
        byte[] ewResp = connectionPool.execute(ewCmd);

        return EWCommand.parseResponse(ewResp, properties.getHeaderLength(), hashId, padMode);
    }

    /**
     * Sign a message using inline LMK-encrypted private key (alternative flow).
     */
    public SigningResult signMessageWithInlineKey(byte[] messageData, byte[] privateKeyLmk,
                                                   String hashId, String padMode) {
        log.info("=== Signing message ({} bytes) with inline key via HSM ===", messageData.length);
        String header = CommandUtils.generateHeader(properties.getHeaderLength());

        byte[] ewCmd = EWCommand.buildWithInlineKey(
                header, hashId, properties.getDefaultSigId(), padMode,
                messageData, privateKeyLmk);

        byte[] ewResp = connectionPool.execute(ewCmd);
        return EWCommand.parseResponse(ewResp, properties.getHeaderLength(), hashId, padMode);
    }

    // ===== 3. VERIFICATION =====

    /**
     * Verify a signature using a public key.
     * Requires the public key to be imported first (EO) to get the MAC.
     * 
     * @param signature     signature bytes to verify
     * @param messageData   original message that was signed
     * @param publicKeyDer  DER-encoded public key to use for verification
     */
    public VerificationResult verifySignature(byte[] signature, byte[] messageData, byte[] publicKeyDer) {
        return verifySignature(signature, messageData, publicKeyDer,
                properties.getDefaultHashId(), properties.getDefaultPadMode());
    }

    /**
     * Verify a signature with specific hash and padding options.
     * This method first imports the public key (EO) to get the MAC,
     * then uses EY to verify.
     */
    public VerificationResult verifySignature(byte[] signature, byte[] messageData,
                                               byte[] publicKeyDer, String hashId, String padMode) {
        log.info("=== Verifying signature via HSM ===");
        String header = CommandUtils.generateHeader(properties.getHeaderLength());

        // Step 1: Import the verification public key via EO to get its MAC
        log.info("Step 1: Importing public key via EO command");
        byte[] eoCmd = EOCommand.build(header, publicKeyDer, new byte[0]);
        byte[] eoResp = connectionPool.execute(eoCmd);
        PublicKeyImportResult importResult = EOCommand.parseResponse(eoResp, properties.getHeaderLength());
        log.info("EO success: MAC={}", importResult.getMacHex());

        // Step 2: Verify signature via EY
        log.info("Step 2: Verifying signature via EY command");
        byte[] eyCmd = EYCommand.build(
                header, hashId, properties.getDefaultSigId(), padMode,
                signature, messageData,
                importResult.getMac(), importResult.getPublicKeyDer(), new byte[0]);

        log.debug("EY command hex: {}", CommandUtils.bytesToHex(eyCmd));
        byte[] eyResp = connectionPool.execute(eyCmd);

        return EYCommand.parseResponse(eyResp, properties.getHeaderLength());
    }

    // ===== UTILITY =====

    /**
     * Import a public key via EO to get its MAC.
     * Useful when you need the MAC for external EY operations.
     */
    public PublicKeyImportResult importPublicKey(byte[] publicKeyDer) {
        String header = CommandUtils.generateHeader(properties.getHeaderLength());
        byte[] eoCmd = EOCommand.build(header, publicKeyDer, new byte[0]);
        byte[] eoResp = connectionPool.execute(eoCmd);
        return EOCommand.parseResponse(eoResp, properties.getHeaderLength());
    }

    /** Get the current key pair (from last generation) */
    public KeyGenerationResult getCurrentKeyPair() {
        return currentKeyPair;
    }

    /** Get the current public key import result (MAC for verification) */
    public PublicKeyImportResult getCurrentPublicKeyImport() {
        return currentPublicKeyImport;
    }

    /** Get connection pool stats */
    public String getPoolStats() {
        return connectionPool.getPoolStats();
    }

    /**
     * Execute a raw command against the HSM.
     * Used for diagnostic commands that don't fit the key/sign/verify pattern.
     */
    public byte[] executeRaw(byte[] command) {
        return connectionPool.execute(command);
    }
}
