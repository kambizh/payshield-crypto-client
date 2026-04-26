package my.com.kambiz.hsm.model;

/**
 * Parsed response from the payShield 10K HSM.
 */
public class PayShieldResponse {

    private final String header;
    private final String responseCode;
    private final String errorCode;
    private final String errorDescription;
    private final byte[] rawResponse;
    private final byte[] payload;

    public PayShieldResponse(String header, String responseCode, String errorCode, byte[] rawResponse, byte[] payload) {
        this.header = header;
        this.responseCode = responseCode;
        this.errorCode = errorCode;
        this.errorDescription = my.com.kambiz.hsm.exception.PayShieldException.decodeErrorCode(errorCode);
        this.rawResponse = rawResponse;
        this.payload = payload;
    }

    public boolean isSuccess() {
        return "00".equals(errorCode);
    }

    public String getHeader() { return header; }
    public String getResponseCode() { return responseCode; }
    public String getErrorCode() { return errorCode; }
    public String getErrorDescription() { return errorDescription; }
    public byte[] getRawResponse() { return rawResponse; }
    public byte[] getPayload() { return payload; }

    /** Get raw response as hex string for debugging */
    public String getRawResponseHex() {
        return bytesToHex(rawResponse);
    }

    /** Get payload as hex string */
    public String getPayloadHex() {
        return payload != null ? bytesToHex(payload) : "";
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return String.format("PayShieldResponse{header='%s', responseCode='%s', errorCode='%s' (%s), payloadLength=%d}",
                header, responseCode, errorCode, errorDescription,
                payload != null ? payload.length : 0);
    }
}
