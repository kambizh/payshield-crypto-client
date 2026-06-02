package my.com.kambiz.hsm.model;

/**
 * Result of CSR generation via QE command.
 *
 * The csrData field contains either:
 *   - Base64-encoded PEM (if CSR Output Format = '0')
 *   - Hex-encoded DER (if CSR Output Format = '1')
 */
public class CsrGenerationResult {

    private final String csrData;
    private final int csrLength;

    public CsrGenerationResult(String csrData, int csrLength) {
        this.csrData = csrData;
        this.csrLength = csrLength;
    }

    /** CSR content (PEM or Hex DER depending on output format requested) */
    public String getCsrData() { return csrData; }

    /** Length of the CSR data in characters */
    public int getCsrLength() { return csrLength; }

    /**
     * Check if the CSR data appears to be PEM format.
     */
    public boolean isPem() {
        return csrData != null && csrData.contains("BEGIN CERTIFICATE REQUEST");
    }

    /**
     * Get the CSR as a properly formatted PEM string (if PEM format).
     * The HSM may return the PEM without line breaks, so this ensures
     * proper formatting.
     */
    public String getFormattedPem() {
        if (!isPem()) return csrData;
        // If already formatted, return as-is
        if (csrData.contains("\n")) return csrData;
        // Otherwise, the HSM returns continuous base64 — split at 64-char lines
        String header = "-----BEGIN CERTIFICATE REQUEST-----";
        String footer = "-----END CERTIFICATE REQUEST-----";
        String b64 = csrData
                .replace(header, "")
                .replace(footer, "")
                .trim();
        StringBuilder sb = new StringBuilder();
        sb.append(header).append("\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append("\n");
        }
        sb.append(footer).append("\n");
        return sb.toString();
    }
}