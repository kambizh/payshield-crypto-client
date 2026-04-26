package my.com.kambiz.hsm.model;

/**
 * Result of RSA key pair generation via EI command.
 * Contains the DER-encoded public key and the LMK-encrypted private key.
 */
public class KeyGenerationResult {

    private final byte[] publicKeyDer;
    private final byte[] privateKeyLmkEncrypted;
    private final int privateKeyLength;
    private final String publicKeyHex;
    private final String privateKeyHex;
    private final int modulusLengthBits;

    public KeyGenerationResult(byte[] publicKeyDer, byte[] privateKeyLmkEncrypted,
                               int privateKeyLength, int modulusLengthBits) {
        this.publicKeyDer = publicKeyDer;
        this.privateKeyLmkEncrypted = privateKeyLmkEncrypted;
        this.privateKeyLength = privateKeyLength;
        this.modulusLengthBits = modulusLengthBits;
        this.publicKeyHex = bytesToHex(publicKeyDer);
        this.privateKeyHex = bytesToHex(privateKeyLmkEncrypted);
    }

    public byte[] getPublicKeyDer() { return publicKeyDer; }
    public byte[] getPrivateKeyLmkEncrypted() { return privateKeyLmkEncrypted; }
    public int getPrivateKeyLength() { return privateKeyLength; }
    public String getPublicKeyHex() { return publicKeyHex; }
    public String getPrivateKeyHex() { return privateKeyHex; }
    public int getModulusLengthBits() { return modulusLengthBits; }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
