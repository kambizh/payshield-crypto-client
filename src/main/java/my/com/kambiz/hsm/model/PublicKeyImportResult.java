package my.com.kambiz.hsm.model;

import my.com.kambiz.hsm.command.CommandUtils;

/**
 * Result of public key import via EO command.
 *
 * Variant LMK:
 *   - mac = 4-byte MAC computed under LMK pair 36-37
 *   - publicKeyDer = DER-encoded public key
 *   - publicKeyBlock = null
 *   - EY uses: MAC + DER public key
 *
 * Key Block LMK:
 *   - mac = null (MAC is embedded inside the key block)
 *   - publicKeyDer = null (DER is wrapped inside the key block)
 *   - publicKeyBlock = full 'S'-prefixed key block blob
 *   - EY uses: the entire S-prefixed blob
 */
public class PublicKeyImportResult {

    private final byte[] mac;
    private final byte[] publicKeyDer;
    private final byte[] publicKeyBlock;
    private final boolean keyBlock;

    /**
     * Variant LMK constructor (original behavior).
     */
    public PublicKeyImportResult(byte[] mac, byte[] publicKeyDer) {
        this.mac = mac;
        this.publicKeyDer = publicKeyDer;
        this.publicKeyBlock = null;
        this.keyBlock = false;
    }

    /**
     * Key Block LMK constructor.
     */
    private PublicKeyImportResult(byte[] publicKeyBlock, boolean keyBlock) {
        this.mac = null;
        this.publicKeyDer = null;
        this.publicKeyBlock = publicKeyBlock;
        this.keyBlock = keyBlock;
    }

    /**
     * Factory for Key Block result.
     */
    public static PublicKeyImportResult keyBlockResult(byte[] publicKeyBlock) {
        return new PublicKeyImportResult(publicKeyBlock, true);
    }

    public byte[] getMac() { return mac; }
    public byte[] getPublicKeyDer() { return publicKeyDer; }
    public byte[] getPublicKeyBlock() { return publicKeyBlock; }
    public boolean isKeyBlock() { return keyBlock; }

    public String getMacHex() {
        return mac != null ? CommandUtils.bytesToHex(mac) : "(embedded in key block)";
    }

    public String getPublicKeyBlockHex() {
        return publicKeyBlock != null ? CommandUtils.bytesToHex(publicKeyBlock) : "";
    }
}