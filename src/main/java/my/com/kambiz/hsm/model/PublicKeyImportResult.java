package my.com.kambiz.hsm.model;

/**
 * Result of public key import via EO command.
 * The MAC is needed for subsequent EY (verify) operations.
 */
public class PublicKeyImportResult {

    private final byte[] mac;
    private final byte[] publicKeyDer;
    private final String macHex;
    private final String publicKeyHex;

    public PublicKeyImportResult(byte[] mac, byte[] publicKeyDer) {
        this.mac = mac;
        this.publicKeyDer = publicKeyDer;
        this.macHex = bytesToHex(mac);
        this.publicKeyHex = bytesToHex(publicKeyDer);
    }

    public byte[] getMac() { return mac; }
    public byte[] getPublicKeyDer() { return publicKeyDer; }
    public String getMacHex() { return macHex; }
    public String getPublicKeyHex() { return publicKeyHex; }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
