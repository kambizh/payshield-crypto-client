package my.com.kambiz.hsm.command;

import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.VerificationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * EY Command - Validate a Digital Signature
 *
 * Variant LMK format:
 *   [Header] EY [HashId:2N] [SigId:2N] [PadMode:2N]
 *   [SigLength:4N] [Signature:binary]
 *   ; [DataLength:4N] [Data:binary]
 *   ; [MAC:4bytes] [PublicKey:DER] [AuthData:optional]
 *
 * Key Block LMK format:
 *   [Header] EY [HashId:2N] [SigId:2N] [PadMode:2N]
 *   [SigLength:4N] [Signature:binary]
 *   ; [DataLength:4N] [Data:binary]
 *   ; [PublicKeyBlock:'S'+keyblock]
 *
 * Key difference: In Key Block mode, after the second ';' delimiter,
 * the entire 'S'-prefixed public key block is sent directly.
 * No separate MAC field. No separate DER. No auth data.
 * The MAC is embedded inside the key block.
 *
 * Response (EZ) format is identical for both modes.
 */
public class EYCommand {

    private static final Logger log = LoggerFactory.getLogger(EYCommand.class);

    private EYCommand() {}

    // ===== VARIANT LMK BUILD (original) =====

    /**
     * Build EY command for Variant LMK.
     * Uses MAC + DER public key + optional auth data.
     */
    public static byte[] build(String header, String hashId, String sigId, String padMode,
                               byte[] signature, byte[] data,
                               byte[] mac, byte[] publicKeyDer, byte[] authData) {
        String sigLen = CommandUtils.formatLength4(signature.length);
        String dataLen = CommandUtils.formatLength4(data.length);

        return CommandUtils.buildCommand(header, "EY",
                hashId, sigId, padMode,
                sigLen, signature,
                ";",
                dataLen, data,
                ";",
                mac,                    // MAC from EO (4 bytes)
                publicKeyDer,           // Public key DER
                authData != null ? authData : new byte[0]
        );
    }

    // ===== KEY BLOCK LMK BUILD =====

    /**
     * Build EY command for Key Block LMK.
     * Uses the full 'S'-prefixed public key block from EO response.
     *
     * @param header          message header
     * @param hashId          hash algorithm
     * @param sigId           signature algorithm
     * @param padMode         padding mode
     * @param signature       signature to verify
     * @param data            original message data
     * @param publicKeyBlock  full 'S'-prefixed key block from EO Key Block response
     */
    public static byte[] buildKeyBlock(String header, String hashId, String sigId, String padMode,
                                       byte[] signature, byte[] data, byte[] publicKeyBlock) {
        String sigLen = CommandUtils.formatLength4(signature.length);
        String dataLen = CommandUtils.formatLength4(data.length);

        log.debug("Building EY (Key Block): sig={} bytes, data={} bytes, pubKeyBlock={} bytes",
                signature.length, data.length, publicKeyBlock.length);

        return CommandUtils.buildCommand(header, "EY",
                hashId, sigId, padMode,
                sigLen, signature,
                ";",
                dataLen, data,
                ";",
                publicKeyBlock          // Full 'S'-prefixed key block (includes embedded MAC)
        );
    }

    // ===== RESPONSE PARSER (identical for both modes) =====

    /**
     * Parse the EZ response into a VerificationResult.
     *
     * Error code 00 = valid signature
     * Error code 01 = MAC verification failure
     * Error code 02 = Signature verification failure
     * Other codes = HSM errors
     */
    public static VerificationResult parseResponse(byte[] response, int headerLength) {
        String respCode = CommandUtils.extractResponseCode(response, headerLength);
        String errCode = CommandUtils.extractErrorCode(response, headerLength);

        if (!"EZ".equals(respCode)) {
            throw new PayShieldException("EY", respCode,
                    "Unexpected response code (expected EZ, got " + respCode + ")");
        }

        boolean valid = "00".equals(errCode);
        String description = PayShieldException.decodeErrorCode(errCode);
        String rawHex = CommandUtils.bytesToHex(response);

        log.info("EY response: errorCode={}, valid={}, description={}", errCode, valid, description);

        return new VerificationResult(valid, errCode, description, rawHex);
    }
}