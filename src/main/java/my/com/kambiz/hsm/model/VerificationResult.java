package my.com.kambiz.hsm.model;

/**
 * Result of signature verification via EY command.
 */
public class VerificationResult {

    private final boolean valid;
    private final String errorCode;
    private final String errorDescription;
    private final String rawResponseHex;

    public VerificationResult(boolean valid, String errorCode, String errorDescription, String rawResponseHex) {
        this.valid = valid;
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
        this.rawResponseHex = rawResponseHex;
    }

    public boolean isValid() { return valid; }
    public String getErrorCode() { return errorCode; }
    public String getErrorDescription() { return errorDescription; }
    public String getRawResponseHex() { return rawResponseHex; }
}
