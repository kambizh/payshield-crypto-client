package my.com.kambiz.hsm.model;

/**
 * Result of RSA key pair generation via EI command.
 * Contains the DER-encoded public key and the LMK-encrypted private key.
 *
 * In Key Block mode:
 *   - privateKeyLmkEncrypted starts with 'S' prefix (key block scheme)
 *   - The entire 'S'-prefixed blob must be passed to EW for signing
 *   - isKeyBlock = true
 *
 * In Variant mode:
 *   - privateKeyLmkEncrypted is the raw LMK-encrypted blob
 *   - isKeyBlock = false
 */
public class KeyGenerationResult {

    private final byte[] publicKeyDer;
    private final byte[] privateKeyLmkEncrypted;
    private final int privateKeyLength;
    private final String publicKeyHex;
    private final String privateKeyHex;
    private final int modulusLengthBits;
    private final boolean keyBlock;

    /**
     * Backward-compatible constructor (Variant LMK assumed).
     */
    public KeyGenerationResult(byte[] publicKeyDer, byte[] privateKeyLmkEncrypted,
                               int privateKeyLength, int modulusLengthBits) {
        this(publicKeyDer, privateKeyLmkEncrypted, privateKeyLength, modulusLengthBits, false);
    }

    /**
     * Full constructor with key block flag.
     */
    public KeyGenerationResult(byte[] publicKeyDer, byte[] privateKeyLmkEncrypted,
                               int privateKeyLength, int modulusLengthBits, boolean keyBlock) {
        this.publicKeyDer = publicKeyDer;
        this.privateKeyLmkEncrypted = privateKeyLmkEncrypted;
        this.privateKeyLength = privateKeyLength;
        this.modulusLengthBits = modulusLengthBits;
        this.keyBlock = keyBlock;
        this.publicKeyHex = bytesToHex(publicKeyDer);
        this.privateKeyHex = bytesToHex(privateKeyLmkEncrypted);
    }

    public byte[] getPublicKeyDer() { return publicKeyDer; }
    public byte[] getPrivateKeyLmkEncrypted() { return privateKeyLmkEncrypted; }
    public int getPrivateKeyLength() { return privateKeyLength; }
    public String getPublicKeyHex() { return publicKeyHex; }
    public String getPrivateKeyHex() { return privateKeyHex; }
    public int getModulusLengthBits() { return modulusLengthBits; }

    /**
     * Whether the private key is in Key Block format ('S' prefix).
     * Determines how EW command constructs the key reference.
     */
    public boolean isKeyBlock() { return keyBlock; }

    /**
     * Returns the LMK scheme description for display/logging.
     */
    public String getLmkScheme() {
        return keyBlock ? "AES Key Block (S-prefix)" : "3DES Variant (raw blob)";
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}