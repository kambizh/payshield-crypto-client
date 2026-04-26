package my.com.kambiz.hsm.command;

import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.VerificationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * EY Command - Validate a Digital Signature
 * 
 * Verifies a signature using an RSA public key. The public key must have
 * been previously imported via EO command to obtain its MAC.
 * 
 * Command format (Section 3.16):
 *   [Header] EY [HashId:2N] [SigId:2N] [PadMode:2N]
 *   [SigLength:4N] [Signature:binary]
 *   ; [DataLength:4N] [Data:binary]
 *   ; [MAC:4bytes] [PublicKey:DER] [AuthData:optional]
 * 
 * Response (EZ):
 *   [Header] EZ [ErrorCode:2A]
 *   ErrorCode 00 = signature valid
 *   ErrorCode 01 = signature verification failure (mismatch)
 */
public class EYCommand {

    private static final Logger log = LoggerFactory.getLogger(EYCommand.class);

    private EYCommand() {}

    /**
     * Build EY command for signature verification.
     * 
     * @param header        message header
     * @param hashId        hash algorithm (must match what was used in EW)
     * @param sigId         signature algorithm: 01=RSA
     * @param padMode       padding mode (must match what was used in EW)
     * @param signature     the signature to verify (binary)
     * @param data          the original message data (binary)
     * @param mac           MAC from EO command (4 bytes)
     * @param publicKeyDer  DER-encoded RSA public key
     * @param authData      authentication data (same as used in EO, or empty)
     */
    public static byte[] build(String header, String hashId, String sigId, String padMode,
                               byte[] signature, byte[] data,
                               byte[] mac, byte[] publicKeyDer, byte[] authData) {
        String sigLen = CommandUtils.formatLength4(signature.length);
        String dataLen = CommandUtils.formatLength4(data.length);

        return CommandUtils.buildCommand(header, "EY",
                hashId,                 // Hash identifier
                sigId,                  // Signature identifier
                padMode,                // Pad mode
                sigLen,                 // Signature length
                signature,              // Signature bytes
                ";",                    // Delimiter
                dataLen,                // Data length
                data,                   // Original message data
                ";",                    // Delimiter
                mac,                    // MAC from EO command (4 bytes)
                publicKeyDer,           // Public key DER
                authData != null ? authData : new byte[0]  // Auth data
        );
    }

    /**
     * Parse the EZ response into a VerificationResult.
     * 
     * Error code 00 = valid signature
     * Error code 01 = MAC verification failure (EO MAC on public key is invalid)
     * Error code 02 = Signature verification failure (signature does not match)
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
