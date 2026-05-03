package my.com.kambiz.hsm.command;

import my.com.kambiz.hsm.config.LmkMode;
import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.PublicKeyImportResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * EO Command - Import a Public Key
 *
 * Variant LMK:
 *   Command:  [Header] EO [Encoding:2N] [PublicKey:DER] [AuthData:optional]
 *   Response: [Header] EP [Error:2A] [MAC:4bytes] [PublicKey:DER]
 *
 * Key Block LMK:
 *   Command:  [Header] EO [Encoding:2N] [PublicKey:DER] ~ # [ModeOfUse:1A]
 *             [KeyVersion:2N] [Exportability:1A] [NumOptBlocks:2N]
 *   Response: [Header] EP [Error:2A] ['S' + PublicKey key block]
 *
 * In Key Block mode:
 *   - No separate MAC field; the MAC is embedded inside the key block
 *   - The response returns 'S' + key block data
 *   - EY uses the entire 'S'-prefixed blob in place of MAC + DER
 */
public class EOCommand {

    private static final Logger log = LoggerFactory.getLogger(EOCommand.class);

    private EOCommand() {}

    // ===== BUILD =====

    /**
     * Build EO command for Variant LMK (original behavior).
     */
    public static byte[] build(String header, byte[] publicKeyDer, byte[] authData) {
        return CommandUtils.buildCommand(header, "EO",
                "01",
                publicKeyDer,
                authData != null ? authData : new byte[0]
        );
    }

    /**
     * Build EO command for Key Block LMK.
     * Requires '~' to terminate public key, then '#' + key block attributes.
     *
     * @param header        message header
     * @param publicKeyDer  DER-encoded RSA public key
     * @param modeOfUse     'V'=Verify (typical for EY usage), 'N'=No restriction
     * @param keyVersion    "00"-"99"
     * @param exportability 'N'=Non-exportable, 'S'=Exportable
     */
    public static byte[] buildKeyBlock(String header, byte[] publicKeyDer,
                                       String modeOfUse, String keyVersion, String exportability) {
        log.debug("Building EO command for Key Block LMK: modeOfUse={}, version={}, export={}",
                modeOfUse, keyVersion, exportability);

        return CommandUtils.buildCommand(header, "EO",
                "01",                   // Encoding rules: DER ASN.1
                publicKeyDer,           // Public key in DER format
                "~",                    // Delimiter: terminates public key + optional auth data
                "#",                    // Key Block delimiter
                modeOfUse,              // Mode of Use (1 char)
                keyVersion,             // Key Version Number (2 chars)
                exportability,          // Exportability (1 char)
                "00"                    // Number of Optional Blocks (2 chars)
        );
    }

    /**
     * Convenience: mode-aware dispatch.
     */
    public static byte[] build(String header, byte[] publicKeyDer, byte[] authData,
                               LmkMode lmkMode, String modeOfUse, String keyVersion, String exportability) {
        if (lmkMode == LmkMode.KEYBLOCK) {
            return buildKeyBlock(header, publicKeyDer, modeOfUse, keyVersion, exportability);
        } else {
            return build(header, publicKeyDer, authData);
        }
    }

    // ===== PARSE =====

    /**
     * Parse EP response for Variant LMK (original behavior).
     * Payload: [MAC:4 bytes] [PublicKey:DER]
     */
    public static PublicKeyImportResult parseResponse(byte[] response, int headerLength) {
        String respCode = CommandUtils.extractResponseCode(response, headerLength);
        String errCode = CommandUtils.extractErrorCode(response, headerLength);

        if (!"EP".equals(respCode)) {
            throw new PayShieldException("EO", respCode,
                    "Unexpected response code (expected EP, got " + respCode + ")");
        }

        if (!"00".equals(errCode)) {
            throw new PayShieldException("EO", errCode,
                    PayShieldException.decodeErrorCode(errCode));
        }

        int offset = headerLength + 4;
        byte[] payload = new byte[response.length - offset];
        System.arraycopy(response, offset, payload, 0, payload.length);

        // First 4 bytes = MAC
        byte[] mac = new byte[4];
        System.arraycopy(payload, 0, mac, 0, 4);

        // Rest = public key DER
        byte[] pubKeyDer = new byte[payload.length - 4];
        System.arraycopy(payload, 4, pubKeyDer, 0, pubKeyDer.length);

        log.info("EO response parsed (VARIANT): MAC={}, pubKey={} bytes",
                CommandUtils.bytesToHex(mac), pubKeyDer.length);

        return new PublicKeyImportResult(mac, pubKeyDer);
    }

    /**
     * Parse EP response for Key Block LMK.
     * Payload: ['S' + key block data] — no separate MAC field.
     *
     * The entire 'S'-prefixed blob is stored as the "public key block".
     * This blob replaces both the MAC and DER in EY commands.
     */
    public static PublicKeyImportResult parseKeyBlockResponse(byte[] response, int headerLength) {
        String respCode = CommandUtils.extractResponseCode(response, headerLength);
        String errCode = CommandUtils.extractErrorCode(response, headerLength);

        if (!"EP".equals(respCode)) {
            throw new PayShieldException("EO", respCode,
                    "Unexpected response code (expected EP, got " + respCode + ")");
        }

        if (!"00".equals(errCode)) {
            throw new PayShieldException("EO", errCode,
                    PayShieldException.decodeErrorCode(errCode));
        }

        int offset = headerLength + 4;
        byte[] payload = new byte[response.length - offset];
        System.arraycopy(response, offset, payload, 0, payload.length);

        // Validate 'S' prefix
        if (payload.length > 0 && payload[0] != 'S') {
            log.warn("Key Block public key does not start with 'S' prefix. First byte: 0x{}",
                    String.format("%02X", payload[0]));
        }

        log.info("EO response parsed (KEY BLOCK): pubKeyBlock={} bytes (S-prefixed)", payload.length);

        // Store the entire S-prefixed blob as the "key block public key"
        // MAC is null — it's embedded inside the key block
        return PublicKeyImportResult.keyBlockResult(payload);
    }

    /**
     * Mode-aware response parser.
     */
    public static PublicKeyImportResult parseResponse(byte[] response, int headerLength, LmkMode lmkMode) {
        if (lmkMode == LmkMode.KEYBLOCK) {
            return parseKeyBlockResponse(response, headerLength);
        } else {
            return parseResponse(response, headerLength);
        }
    }
}