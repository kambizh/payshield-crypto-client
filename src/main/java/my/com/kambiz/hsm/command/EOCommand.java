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
 * Shared-port multi-LMK (Key Block): insert "%{lmkId}" after '~' and before '#',
 * e.g. ...~%01#V00N00  (same placement idea as EI's % before #).
 * Variant LMK: callers may append "%{lmkId}" at the end via {@link CommandUtils#withLmkId}.
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
     * Build EO command for Key Block LMK (dual-port / no LMK Identifier).
     */
    public static byte[] buildKeyBlock(String header, byte[] publicKeyDer,
                                       String modeOfUse, String keyVersion, String exportability) {
        return buildKeyBlock(header, publicKeyDer, modeOfUse, keyVersion, exportability, null);
    }

    /**
     * Build EO command for Key Block LMK, optionally with LMK Identifier for shared-port hosts.
     *
     * When {@code lmkId} is set (e.g. "01"):
     *   EO 01 [pubkey] ~ %01 # V 00 N 00
     * When blank/null (dual-port lab):
     *   EO 01 [pubkey] ~ # V 00 N 00
     */
    public static byte[] buildKeyBlock(String header, byte[] publicKeyDer,
                                       String modeOfUse, String keyVersion, String exportability,
                                       String lmkId) {
        log.debug("Building EO command for Key Block LMK: modeOfUse={}, version={}, export={}, lmkId={}",
                modeOfUse, keyVersion, exportability,
                lmkId == null || lmkId.isBlank() ? "(none)" : lmkId);

        if (lmkId != null && !lmkId.isBlank()) {
            return CommandUtils.buildCommand(header, "EO",
                    "01",
                    publicKeyDer,
                    "~",
                    "%", lmkId,
                    "#",
                    modeOfUse,
                    keyVersion,
                    exportability,
                    "00"
            );
        }
        return CommandUtils.buildCommand(header, "EO",
                "01",
                publicKeyDer,
                "~",
                "#",
                modeOfUse,
                keyVersion,
                exportability,
                "00"
        );
    }

    /**
     * Convenience: mode-aware dispatch.
     */
    public static byte[] build(String header, byte[] publicKeyDer, byte[] authData,
                               LmkMode lmkMode, String modeOfUse, String keyVersion, String exportability) {
        return build(header, publicKeyDer, authData, lmkMode, modeOfUse, keyVersion, exportability, null);
    }

    /**
     * Convenience: mode-aware dispatch with optional LMK Identifier.
     */
    public static byte[] build(String header, byte[] publicKeyDer, byte[] authData,
                               LmkMode lmkMode, String modeOfUse, String keyVersion, String exportability,
                               String lmkId) {
        if (lmkMode == LmkMode.KEYBLOCK) {
            return buildKeyBlock(header, publicKeyDer, modeOfUse, keyVersion, exportability, lmkId);
        } else {
            return CommandUtils.withLmkId(build(header, publicKeyDer, authData), lmkId);
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