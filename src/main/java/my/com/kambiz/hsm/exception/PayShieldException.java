package my.com.kambiz.hsm.exception;

/**
 * Exception thrown when HSM communication or command execution fails.
 */
public class PayShieldException extends RuntimeException {

    private final String errorCode;
    private final String commandCode;

    public PayShieldException(String message) {
        super(message);
        this.errorCode = null;
        this.commandCode = null;
    }

    public PayShieldException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = null;
        this.commandCode = null;
    }

    public PayShieldException(String commandCode, String errorCode, String message) {
        super(String.format("HSM command [%s] failed with error code [%s]: %s",
                commandCode, errorCode, message));
        this.errorCode = errorCode;
        this.commandCode = commandCode;
    }

    public String getErrorCode() { return errorCode; }
    public String getCommandCode() { return commandCode; }

    /**
     * Decode payShield error codes to human-readable descriptions.
     * Reference: payShield 10K Core Host Command Manual.
     */
    public static String decodeErrorCode(String errorCode) {
        return switch (errorCode) {
            case "00" -> "No error";
            case "01" -> "Verification failure (signature mismatch)";
            case "02" -> "Inappropriate key length";
            case "03" -> "Invalid message source address";
            case "04" -> "Invalid key type code";
            case "05" -> "Invalid key length flag";
            case "10" -> "Source key parity error";
            case "11" -> "Destination key parity error";
            case "12" -> "Contents of user storage not available";
            case "13" -> "Invalid LMK scheme";
            case "14" -> "PIN encrypted under LMK pair 02-03 is invalid";
            case "15" -> "Invalid input data (invalid pad character/length)";
            case "16" -> "Console or supervisor is not connected via this device";
            case "17" -> "HSM is not in the Authorized state";
            case "19" -> "HSM is not in the correct mode";
            case "20" -> "PIN block does not contain valid values";
            case "21" -> "Invalid index value or index not found";
            case "22" -> "Invalid number of components";
            case "26" -> "HSM buffer overflow";
            case "27" -> "HSM buffer contains one to many commands";
            case "29" -> "Key status does not match";
            case "30" -> "Data length not valid";
            case "33" -> "LMK key change storage is corrupted";
            case "40" -> "Invalid firmware checksum";
            case "41" -> "Internal hardware/software error: bad host header length";
            case "42" -> "No room in user storage for DES tables (dec. table)";
            case "68" -> "Command not available or disabled";
            case "75" -> "HSM is in old LMK mode";
            case "76" -> "RSA key generation failure (key gen hardware)";
            case "80" -> "Data length error (public key DER encoding)";
            case "81" -> "Invalid key usage";
            case "82" -> "No private key found in user storage at specified index";
            case "90" -> "Data parity error in the request message received by the HSM";
            case "91" -> "Command not licensed / feature not available";
            case "A1" -> "Incompatible LMK scheme of key in user storage";
            case "A2" -> "Incompatible key block LMK identifier";
            case "A3" -> "Incompatible key block export type";
            default -> "Unknown error code: " + errorCode;
        };
    }
}
