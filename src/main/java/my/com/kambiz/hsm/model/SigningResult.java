package my.com.kambiz.hsm.model;

/**
 * Result of digital signature generation via EW command.
 */
public class SigningResult {

    private final byte[] signature;
    private final String signatureHex;
    private final int signatureLength;
    private final String hashAlgorithm;
    private final String padMode;

    public SigningResult(byte[] signature, String hashAlgorithm, String padMode) {
        this.signature = signature;
        this.signatureHex = bytesToHex(signature);
        this.signatureLength = signature.length;
        this.hashAlgorithm = hashAlgorithm;
        this.padMode = padMode;
    }

    public byte[] getSignature() { return signature; }
    public String getSignatureHex() { return signatureHex; }
    public int getSignatureLength() { return signatureLength; }
    public String getHashAlgorithm() { return hashAlgorithm; }
    public String getPadMode() { return padMode; }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
