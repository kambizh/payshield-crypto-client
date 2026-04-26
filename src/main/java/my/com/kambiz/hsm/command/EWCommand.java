package my.com.kambiz.hsm.command;

import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.SigningResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * EW Command - Generate a Digital Signature
 * 
 * Uses the RSA private key stored in HSM user storage (via LA command).
 * 
 * Command format (variant LMK, key in user storage - Section 3.14):
 *   [Header] EW [HashId:2N] [SigId:2N] [PadMode:2N] [DataLen:4N] [Data:binary]
 *   ; [PrivKeyFlag:2N=99] [PrivKeyLen:4N] K[StorageIndex:3H]
 * 
 * PrivKeyFlag 99 = key identified below
 *   When followed by "K000", the HSM knows it's a user storage reference.
 *   PrivKeyLen = length of the reference string (e.g., "0004" for "K000")
 * 
 * Response (EX):
 *   [Header] EX [ErrorCode:2A] [SigLength:4N] [Signature:binary]
 */
public class EWCommand {

    private static final Logger log = LoggerFactory.getLogger(EWCommand.class);

    private EWCommand() {}

    /**
     * Build EW command using private key stored in HSM user storage.
     * 
     * @param header        message header
     * @param hashId        hash algorithm: 01=SHA-1, 05=SHA-256, etc.
     * @param sigId         signature algorithm: 01=RSA
     * @param padMode       padding: 01=PKCS#1 v1.5
     * @param data          message data to sign (raw bytes)
     * @param storageIndex  user storage index: e.g., "000"
     */
    public static byte[] buildWithUserStorage(String header, String hashId, String sigId,
                                              String padMode, byte[] data, String storageIndex) {
        String dataLen = CommandUtils.formatLength4(data.length);
        // Key reference: "K" + 3-char hex index = 4 chars total
        String keyRef = "K" + storageIndex;
        String keyRefLen = CommandUtils.formatLength4(keyRef.length());

        return CommandUtils.buildCommand(header, "EW",
                hashId,                 // Hash identifier
                sigId,                  // Signature identifier
                padMode,                // Pad mode
                dataLen,                // Data length (4-digit decimal)
                data,                   // Message data (binary)
                ";",                    // Delimiter
                "99",                   // Private key flag: 99 = key identified below (K000 ref or inline)
                keyRefLen,              // Private key reference length
                keyRef                  // "K000" = user storage index 000
        );
    }

    /**
     * Build EW command with the LMK-encrypted private key provided directly in the command.
     * (Alternative to user storage — useful for testing)
     * 
     * @param header         message header
     * @param hashId         hash algorithm
     * @param sigId          signature algorithm
     * @param padMode        padding mode
     * @param data           message data to sign
     * @param privateKeyLmk  LMK-encrypted private key (raw bytes)
     */
    public static byte[] buildWithInlineKey(String header, String hashId, String sigId,
                                            String padMode, byte[] data, byte[] privateKeyLmk) {
        String dataLen = CommandUtils.formatLength4(data.length);
        String privKeyLen = CommandUtils.formatLength4(privateKeyLmk.length);

        return CommandUtils.buildCommand(header, "EW",
                hashId,                 // Hash identifier
                sigId,                  // Signature identifier
                padMode,                // Pad mode
                dataLen,                // Data length
                data,                   // Message data
                ";",                    // Delimiter
                "99",                   // Private key flag: 99 = key follows
                privKeyLen,             // Private key length
                privateKeyLmk           // LMK-encrypted private key
        );
    }

    /**
     * Parse the EX response into a SigningResult.
     * Payload after header + "EX" + "00":
     *   [SigLength:4N] [Signature:binary]
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
