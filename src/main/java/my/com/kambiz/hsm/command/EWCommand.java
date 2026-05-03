package my.com.kambiz.hsm.command;

import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.SigningResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * EW Command - Generate a Digital Signature
 *
 * Variant LMK - inline key (Section 3.13):
 *   [Header] EW [HashId:2N] [SigId:2N] [PadMode:2N] [DataLen:4N] [Data:binary]
 *   ; [PrivKeyFlag:2N=99] [PrivKeyLen:4N] [PrivKey:bytes]
 *
 * Variant LMK - user storage (Section 3.14):
 *   [Header] EW [HashId:2N] [SigId:2N] [PadMode:2N] [DataLen:4N] [Data:binary]
 *   ; [PrivKeyFlag:2N=99] [PrivKeyLen:4N] K[Index:3H]
 *
 * Key Block LMK - inline key:
 *   [Header] EW [HashId:2N] [SigId:2N] [PadMode:2N] [DataLen:4N] [Data:binary]
 *   ; [PrivKeyFlag:2N=99] [PrivKeyLen:4H=FFFF] [PrivKey:'S'+keyblock]
 *
 * Key Block LMK - user storage (Section 3.15):
 *   [Header] EW [HashId:2N] [SigId:2N] [PadMode:2N] [DataLen:4N] [Data:binary]
 *   ; [PrivKeyFlag:2N=99] [PrivKeyLen:4H=FFFF] SK[Index:3H]
 *
 * Key differences for Key Block:
 *   1. Private key length field is "FFFF" (hex, reserved) instead of decimal byte count
 *   2. Inline key: pass the full 'S'-prefixed blob from EI response
 *   3. User storage ref: "SK{index}" instead of "K{index}"
 *      ('S' = key block scheme, 'K' = index flag, then 3-hex-char index)
 *
 * Response (EX) format is identical for both modes.
 */
public class EWCommand {

    private static final Logger log = LoggerFactory.getLogger(EWCommand.class);

    private EWCommand() {}

    // ===== VARIANT LMK BUILDERS (unchanged) =====

    /**
     * Build EW command using private key stored in HSM user storage (Variant LMK).
     */
    public static byte[] buildWithUserStorage(String header, String hashId, String sigId,
                                              String padMode, byte[] data, String storageIndex) {
        String dataLen = CommandUtils.formatLength4(data.length);
        String keyRef = "K" + storageIndex;
        String keyRefLen = CommandUtils.formatLength4(keyRef.length());

        return CommandUtils.buildCommand(header, "EW",
                hashId, sigId, padMode,
                dataLen, data,
                ";",
                "99", keyRefLen, keyRef
        );
    }

    /**
     * Build EW command with LMK-encrypted private key inline (Variant LMK).
     */
    public static byte[] buildWithInlineKey(String header, String hashId, String sigId,
                                            String padMode, byte[] data, byte[] privateKeyLmk) {
        String dataLen = CommandUtils.formatLength4(data.length);
        String privKeyLen = CommandUtils.formatLength4(privateKeyLmk.length);

        return CommandUtils.buildCommand(header, "EW",
                hashId, sigId, padMode,
                dataLen, data,
                ";",
                "99", privKeyLen, privateKeyLmk
        );
    }

    // ===== KEY BLOCK LMK BUILDERS =====

    /**
     * Build EW command with Key Block LMK-encrypted private key inline.
     *
     * The privateKeyKeyBlock parameter must be the full 'S'-prefixed blob
     * returned by EI in Key Block mode.
     *
     * @param header           message header
     * @param hashId           hash algorithm
     * @param sigId            signature algorithm
     * @param padMode          padding mode
     * @param data             message data to sign
     * @param privateKeyKeyBlock  'S'-prefixed key block blob from EI response
     */
    public static byte[] buildKeyBlockWithInlineKey(String header, String hashId, String sigId,
                                                    String padMode, byte[] data,
                                                    byte[] privateKeyKeyBlock) {
        String dataLen = CommandUtils.formatLength4(data.length);

        log.debug("Building EW (Key Block inline): privKey={} bytes, data={} bytes, first byte=0x{}",
                privateKeyKeyBlock.length, data.length,
                String.format("%02X", privateKeyKeyBlock[0]));

        return CommandUtils.buildCommand(header, "EW",
                hashId, sigId, padMode,
                dataLen, data,
                ";",
                "99",                       // Private key flag: key follows
                "FFFF",                      // Key Block: length always "FFFF"
                privateKeyKeyBlock           // Full 'S'-prefixed key block blob
        );
    }

    /**
     * Build EW command using private key stored in HSM user storage (Key Block LMK).
     *
     * Key Block user storage reference format: "SK{index}"
     *   'S' = Key Block scheme identifier
     *   'K' = Index flag (always 'K')
     *   index = 3-char hex storage index (e.g., "022")
     *
     * @param header        message header
     * @param hashId        hash algorithm
     * @param sigId         signature algorithm
     * @param padMode       padding mode
     * @param data          message data to sign
     * @param storageIndex  user storage index (e.g., "022")
     */
    public static byte[] buildKeyBlockWithUserStorage(String header, String hashId, String sigId,
                                                      String padMode, byte[] data,
                                                      String storageIndex) {
        String dataLen = CommandUtils.formatLength4(data.length);
        // Key Block user storage reference: S + K + index
        String keyRef = "SK" + storageIndex;

        log.debug("Building EW (Key Block user storage): ref={}, data={} bytes", keyRef, data.length);

        return CommandUtils.buildCommand(header, "EW",
                hashId, sigId, padMode,
                dataLen, data,
                ";",
                "99",                       // Private key flag
                "FFFF",                      // Key Block: length always "FFFF"
                keyRef                       // "SK022" etc.
        );
    }

    // ===== MODE-AWARE CONVENIENCE BUILDERS =====

    /**
     * Build EW command with inline key, auto-selecting Variant or Key Block format
     * based on whether the key blob starts with 'S'.
     */
    public static byte[] buildWithInlineKeyAuto(String header, String hashId, String sigId,
                                                String padMode, byte[] data,
                                                byte[] privateKey, boolean isKeyBlock) {
        if (isKeyBlock) {
            return buildKeyBlockWithInlineKey(header, hashId, sigId, padMode, data, privateKey);
        } else {
            return buildWithInlineKey(header, hashId, sigId, padMode, data, privateKey);
        }
    }

    // ===== RESPONSE PARSER (identical for both modes) =====

    /**
     * Parse the EX response into a SigningResult.
     * Payload after header + "EX" + "00":
     *   [SigLength:4N] [Signature:binary]
     *
     * Response format is the same for Variant and Key Block.
     */
    public static SigningResult parseResponse(byte[] response, int headerLength,
                                              String hashId, String padMode) {
        String respCode = CommandUtils.extractResponseCode(response, headerLength);
        String errCode = CommandUtils.extractErrorCode(response, headerLength);

        if (!"EX".equals(respCode)) {
            throw new PayShieldException("EW", respCode,
                    "Unexpected response code (expected EX, got " + respCode + ")");
        }

        if (!"00".equals(errCode)) {
            throw new PayShieldException("EW", errCode,
                    PayShieldException.decodeErrorCode(errCode));
        }

        int offset = headerLength + 4; // header + "EX" + "00"

        // 4-digit decimal signature length
        String sigLenStr = new String(response, offset, 4, StandardCharsets.US_ASCII);
        int sigLen = Integer.parseInt(sigLenStr);
        offset += 4;

        // Signature bytes
        byte[] signature = new byte[sigLen];
        System.arraycopy(response, offset, signature, 0, sigLen);

        log.info("EW response parsed: signature={} bytes, hash={}, pad={}",
                sigLen, CommandUtils.decodeHashAlgorithm(hashId),
                CommandUtils.decodePadMode(padMode));

        return new SigningResult(signature,
                CommandUtils.decodeHashAlgorithm(hashId),
                CommandUtils.decodePadMode(padMode));
    }
}