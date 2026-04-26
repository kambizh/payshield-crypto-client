package my.com.kambiz.hsm.command;

import my.com.kambiz.hsm.exception.PayShieldException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * LA Command - Load Data to User Storage
 * 
 * Used to store the LMK-encrypted RSA private key into HSM user storage
 * so that EW (sign) can reference it by index (K000) instead of sending
 * the entire encrypted key in every request.
 * 
 * Command format (variable block size):
 *   [Header] LA [IndexFlag:1A] [Index:3H] [DataLength:4N] [Data:variable]
 * 
 * Response (LB):
 *   [Header] LB [ErrorCode:2A]
 * 
 * IndexFlag: B = Binary, K = Key
 * Index: 000-FFF (hex), 000-07F supports up to 1000 bytes
 */
public class LACommand {

    private static final Logger log = LoggerFactory.getLogger(LACommand.class);

    private LACommand() {}

    /**
     * Build LA command to store LMK-encrypted RSA private key.
     * Uses Binary index flag and variable block size.
     */
    public static byte[] build(String header, String storageIndex, byte[] privateKeyLmkEncrypted) {
        String dataLength = CommandUtils.formatLength4(privateKeyLmkEncrypted.length);

        return CommandUtils.buildCommand(header, "LA",
                "B",                    // Index flag: B = Binary
                storageIndex,           // Index: e.g., "000"
                dataLength,             // Data length
                privateKeyLmkEncrypted  // The LMK-encrypted private key data
        );
    }

    /**
     * Verify the LB response is success.
     */
    public static void verifyResponse(byte[] response, int headerLength) {
        String respCode = CommandUtils.extractResponseCode(response, headerLength);
        String errCode = CommandUtils.extractErrorCode(response, headerLength);

        if (!"LB".equals(respCode)) {
            throw new PayShieldException("LA", respCode,
                    "Unexpected response code (expected LB, got " + respCode + ")");
        }

        if (!"00".equals(errCode)) {
            throw new PayShieldException("LA", errCode,
                    PayShieldException.decodeErrorCode(errCode));
        }

        log.info("LA command successful - private key stored in HSM user storage");
    }
}
