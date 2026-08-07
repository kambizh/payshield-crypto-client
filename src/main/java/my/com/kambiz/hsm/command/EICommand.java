package my.com.kambiz.hsm.command;

import my.com.kambiz.hsm.config.LmkMode;
import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.KeyGenerationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * EI Command - Generate RSA Key Pair
 *
 * Variant LMK command format:
 *   [Header] EI [KeyType:1N] [ModulusLength:4N] [EncodingRules:2N]
 *
 * Key Block LMK command format:
 *   [Header] EI [KeyType:1N] [ModulusLength:4N] [EncodingRules:2N]
 *   # [KeyVersion:2N] [NumOptBlocks:2N]
 *
 * Shared-port multi-LMK (optional): insert "%{LMK Identifier}" before '#':
 *   Variant:   [Header] EI ... %00 #0000
 *   Key Block: [Header] EI ... %01 #0000
 * Example: 0000EI0204801%01#0000
 *
 * Response (EJ):
 *   Variant:  [Header] EJ [Error:2A] [PubKey:DER] [PrivKeyLen:4N]       [PrivKey:bytes]
 *   KeyBlock: [Header] EJ [Error:2A] [PubKey:DER] [PrivKeyLen:4H=FFFF]  ['S' + PrivKey:keyblock]
 *
 * Key differences in Key Block mode:
 *   1. Build: optional "%{lmkId}" + '#' + Key Version + Num Optional Blocks
 *   2. Response: Private key length field is always "FFFF" (hex, reserved)
 *   3. Response: Private key blob starts with 'S' prefix (Key Block scheme identifier)
 *   4. The 'S'-prefixed blob is what you pass back in EW for signing
 */
public class EICommand {

    private static final Logger log = LoggerFactory.getLogger(EICommand.class);

    private EICommand() {}

    // ===== BUILD =====

    /**
     * Build EI command for Variant LMK (legacy / dual-port).
     * No LMK Identifier and no '#' section.
     */
    public static byte[] build(String header, int keyType, int modulusBits, String encoding) {
        return buildVariant(header, keyType, modulusBits, encoding, null, "00");
    }

    /**
     * Build EI for Variant with optional LMK Identifier (shared-port).
     * When {@code lmkId} is set (e.g. "00"):
     *   EI ... %00 #0000
     * When blank: classic Variant with no '%' / '#' trailer.
     */
    public static byte[] buildVariant(String header, int keyType, int modulusBits, String encoding,
                                      String lmkId, String keyVersion) {
        if (lmkId != null && !lmkId.isBlank()) {
            log.info("Building EI command for Variant LMK with LMK id={}: keyType={}, bits={}",
                    lmkId, keyType, modulusBits);
            return CommandUtils.buildCommand(header, "EI",
                    String.valueOf(keyType),
                    String.format("%04d", modulusBits),
                    encoding,
                    "%", lmkId,
                    "#", keyVersion != null ? keyVersion : "00", "00"
            );
        }
        return CommandUtils.buildCommand(header, "EI",
                String.valueOf(keyType),
                String.format("%04d", modulusBits),
                encoding
        );
    }

    /**
     * Build EI command for Key Block LMK (dual-port, no LMK Identifier).
     * Appends '#' + Key Version + Num Optional Blocks.
     *
     * IMPORTANT: The EI command's Key Block section is DIFFERENT from other commands
     * like EO/FY. Per the spec (page 189), EI only has TWO fields after '#':
     *   1. Key Version Number (2N)
     *   2. Number of Optional Blocks (2N)
     *
     * Mode of Use and Exportability are NOT specified here — they are automatically
     * determined by the Key Type Indicator.
     */
    public static byte[] buildKeyBlock(String header, int keyType, int modulusBits, String encoding,
                                       String keyVersion) {
        return buildKeyBlock(header, keyType, modulusBits, encoding, keyVersion, null);
    }

    /**
     * Build EI command for Key Block LMK, optionally with LMK Identifier for shared-port hosts.
     *
     * When {@code lmkId} is set (e.g. "01"), the wire format is:
     *   EI [KeyType] [ModulusLength] [Encoding] % [lmkId] # [KeyVersion] [NumOptBlocks]
     * Example: 0000EI0204801%01#0000
     *
     * When {@code lmkId} is null/blank (dual-port lab):
     *   EI [KeyType] [ModulusLength] [Encoding] # [KeyVersion] [NumOptBlocks]
     */
    public static byte[] buildKeyBlock(String header, int keyType, int modulusBits, String encoding,
                                       String keyVersion, String lmkId) {
        log.info("Building EI command for Key Block LMK: keyType={}, bits={}, version={}, lmkId={}",
                keyType, modulusBits, keyVersion, lmkId == null || lmkId.isBlank() ? "(none)" : lmkId);

        if (lmkId != null && !lmkId.isBlank()) {
            return CommandUtils.buildCommand(header, "EI",
                    String.valueOf(keyType),
                    String.format("%04d", modulusBits),
                    encoding,
                    "%", lmkId,
                    "#", keyVersion, "00"
            );
        }
        return CommandUtils.buildCommand(header, "EI",
                String.valueOf(keyType),
                String.format("%04d", modulusBits),
                encoding,
                "#", keyVersion, "00"
        );
    }

    /**
     * Convenience: build EI with mode-aware dispatch.
     * Selects Variant or Key Block format based on the LmkMode.
     * Pass a non-blank {@code lmkId} for shared-port multi-LMK hosts.
     */
    public static byte[] build(String header, int keyType, int modulusBits, String encoding,
                               LmkMode lmkMode, String keyVersion, String lmkId) {
        if (lmkMode == LmkMode.KEYBLOCK) {
            return buildKeyBlock(header, keyType, modulusBits, encoding, keyVersion, lmkId);
        } else {
            return buildVariant(header, keyType, modulusBits, encoding, lmkId, keyVersion);
        }
    }

    /**
     * Convenience: mode-aware build without LMK Identifier (dual-port).
     */
    public static byte[] build(String header, int keyType, int modulusBits, String encoding,
                               LmkMode lmkMode, String keyVersion) {
        return build(header, keyType, modulusBits, encoding, lmkMode, keyVersion, null);
    }

    // ===== PARSE =====

    /**
     * Parse EJ response — auto-detects Variant vs Key Block format.
     *
     * Both formats share the same structure up to the private key length field:
     *   [Header][EJ][00][PublicKey DER][PrivKeyLen 4 chars][PrivKey blob]
     *
     * Detection: if the 4-char length field reads "FFFF" → Key Block mode.
     * In Key Block mode, the private key blob starts with 'S' (0x53 ASCII).
     */
    public static KeyGenerationResult parseResponse(byte[] response, int headerLength, int modulusBits) {
        String respCode = CommandUtils.extractResponseCode(response, headerLength);
        String errCode = CommandUtils.extractErrorCode(response, headerLength);

        if (!"EJ".equals(respCode)) {
            throw new PayShieldException("EI", respCode,
                    "Unexpected response code (expected EJ, got " + respCode + ")");
        }

        if (!"00".equals(errCode)) {
            throw new PayShieldException("EI", errCode,
                    PayShieldException.decodeErrorCode(errCode));
        }

        // Payload starts after header + "EJ" + "00"
        int offset = headerLength + 4;
        byte[] payload = new byte[response.length - offset];
        System.arraycopy(response, offset, payload, 0, payload.length);

        // Parse DER-encoded public key
        int pubKeyLen = parseDerLength(payload, 0);
        byte[] publicKeyDer = new byte[pubKeyLen];
        System.arraycopy(payload, 0, publicKeyDer, 0, pubKeyLen);

        // Read the 4-char private key length field
        int privLenOffset = pubKeyLen;
        String privLenStr = new String(payload, privLenOffset, 4, StandardCharsets.US_ASCII);

        byte[] privateKey;
        int privKeyLen;
        boolean isKeyBlock;

        if ("FFFF".equalsIgnoreCase(privLenStr)) {
            // ===== KEY BLOCK MODE =====
            // Length field is "FFFF" (reserved). Private key follows immediately
            // as 'S' + key block data, extending to end of payload.
            isKeyBlock = true;
            int privKeyOffset = privLenOffset + 4;
            privKeyLen = payload.length - privKeyOffset;
            privateKey = new byte[privKeyLen];
            System.arraycopy(payload, privKeyOffset, privateKey, 0, privKeyLen);

            // Validate 'S' prefix
            if (privKeyLen > 0 && privateKey[0] != 'S') {
                log.warn("Key Block private key does not start with 'S' prefix. First byte: 0x{}", 
                        String.format("%02X", privateKey[0]));
            }

            log.info("EI response parsed (KEY BLOCK): pubKey={} bytes, privKey={} bytes (S-prefixed key block), modulus={} bits",
                    pubKeyLen, privKeyLen, modulusBits);
        } else {
            // ===== VARIANT MODE =====
            // Length field is a 4-digit decimal byte count.
            isKeyBlock = false;
            privKeyLen = Integer.parseInt(privLenStr);
            int privKeyOffset = privLenOffset + 4;
            privateKey = new byte[privKeyLen];
            System.arraycopy(payload, privKeyOffset, privateKey, 0, privKeyLen);

            log.info("EI response parsed (VARIANT): pubKey={} bytes, privKey={} bytes (LMK-encrypted), modulus={} bits",
                    pubKeyLen, privKeyLen, modulusBits);
        }

        return new KeyGenerationResult(publicKeyDer, privateKey, privKeyLen, modulusBits, isKeyBlock);
    }

    /**
     * Parse a DER-encoded structure to determine its total length (tag + length + content).
     * Handles both short-form and long-form length encoding.
     */
    private static int parseDerLength(byte[] data, int startOffset) {
        if (data.length <= startOffset + 1) {
            throw new PayShieldException("DER data too short to parse");
        }

        // Skip the tag byte (0x30 for SEQUENCE)
        int offset = startOffset + 1;

        int firstByte = data[offset] & 0xFF;
        offset++;

        int contentLength;
        if (firstByte < 0x80) {
            // Short form: length is the byte itself
            contentLength = firstByte;
        } else {
            // Long form: firstByte & 0x7F = number of subsequent bytes encoding the length
            int numLenBytes = firstByte & 0x7F;
            contentLength = 0;
            for (int i = 0; i < numLenBytes; i++) {
                contentLength = (contentLength << 8) | (data[offset] & 0xFF);
                offset++;
            }
        }

        // Total = header bytes consumed + content length
        int totalLength = (offset - startOffset) + contentLength;

        log.debug("DER total length from offset {}: {} bytes (content: {} bytes)", startOffset, totalLength, contentLength);
        return totalLength;
    }
}