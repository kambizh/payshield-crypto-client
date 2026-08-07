package my.com.kambiz.hsm.config;

import jakarta.validation.constraints.*;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration properties for payShield 10K HSM connection.
 * Firmware 2.2b backward-compatible with 1.7a host command set.
 *
 * Dual-port architecture:
 *   port     = Variant LMK port (1501) — used when lmk-mode=variant
 *   portKeyBlock = AES Key Block LMK port (1502) — used when lmk-mode=keyblock
 *
 * The active port is determined by the lmk-mode property.
 */
@Validated
@ConfigurationProperties(prefix = "payshield")
public class PayShieldProperties {

    /** HSM host IP or hostname — must be set by the caller */
    @NotBlank(message = "payshield.host must be set")
    private String host = "127.0.0.1";

    /** HSM host command port for Variant LMK (typically 1501) */
    @Min(value = 1, message = "payshield.port must be between 1 and 65535")
    @Max(value = 65535, message = "payshield.port must be between 1 and 65535")
    private int port = 1501;

    /** HSM host command port for AES Key Block LMK (typically 1502) */
    @Min(value = 1, message = "payshield.port-key-block must be between 1 and 65535")
    @Max(value = 65535, message = "payshield.port-key-block must be between 1 and 65535")
    private int portKeyBlock = 1502;

    /**
     * LMK operating mode: "variant" or "keyblock".
     * Controls which port is used and how commands are constructed/parsed.
     */
    @Pattern(regexp = "variant|keyblock", message = "payshield.lmk-mode must be 'variant' or 'keyblock'")
    private String lmkMode = "keyblock";

    /**
     * Optional LMK Identifier for shared-port multi-LMK hosts (2 digits).
     * When set, EI appends "%{id}" before the '#' section, e.g.:
     *   00 → Variant   → ...%00#0000
     *   01 → Key Block → ...%01#0000
     * Leave blank to omit (port-based LMK selection, dual-port lab).
     */
    @Pattern(regexp = "|[0-9]{2}", message = "payshield.lmk-id must be blank or two digits (e.g. 00, 01)")
    private String lmkId = "";

    /** Message header length configured on the HSM — must be 0, 2, or 4 */
    @Min(value = 0, message = "payshield.header-length must be 0, 2, or 4")
    @Max(value = 4, message = "payshield.header-length must be 0, 2, or 4")
    private int headerLength = 4;

    /** Connection timeout in milliseconds */
    @Min(value = 100, message = "payshield.connect-timeout-ms must be at least 100ms")
    private int connectTimeoutMs = 5000;

    /** Read/response timeout in milliseconds */
    @Min(value = 100, message = "payshield.read-timeout-ms must be at least 100ms")
    private int readTimeoutMs = 10000;

    /** Must be true — payShield 10K always uses 2-byte length-prefix TCP framing */
    @AssertTrue(message = "payshield.length-prefix-enabled must be true; payShield 10K requires 2-byte length-prefix framing")
    private boolean lengthPrefixEnabled = true;

    /** Connection pool: max total connections (concurrent HSM operations) */
    @Min(value = 1, message = "payshield.pool-max-total must be at least 1")
    private int poolMaxTotal = 5;

    /** Connection pool: max idle connections */
    @Min(value = 0, message = "payshield.pool-max-idle must be >= 0")
    private int poolMaxIdle = 3;

    /** Connection pool: min idle connections */
    @Min(value = 0, message = "payshield.pool-min-idle must be >= 0")
    private int poolMinIdle = 1;

    /** Connection pool: max wait time (ms) to borrow a connection before throwing an error.
     *  Prevents indefinite blocking when all connections are in use. */
    @Min(value = 100, message = "payshield.pool-borrow-timeout-ms must be at least 100ms")
    private long poolBorrowTimeoutMs = 5000;

    /** User storage index for RSA private key (000-FFF) */
    private String privateKeyStorageIndex = "000";

    /** Default RSA modulus length in bits */
    @Min(value = 512, message = "payshield.default-modulus-length minimum is 512")
    @Max(value = 4096, message = "payshield.default-modulus-length maximum is 4096")
    private int defaultModulusLength = 2048;

    /** Hash algorithm ID: 01=SHA-1, 02=MD5, 04=NoHash, 05=SHA-224, 06=SHA-256, 07=SHA-384, 08=SHA-512 */
    @Pattern(regexp = "0[1-8]", message = "payshield.default-hash-id must be 01-08")
    private String defaultHashId = "06";

    /** Signature algorithm ID: 01=RSA */
    @Pattern(regexp = "01", message = "payshield.default-sig-id must be '01' (RSA)")
    private String defaultSigId = "01";

    /** Pad mode: 01=PKCS#1 v1.5, 02=ANSI X9.31, 03=ISO 9796, 04=PSS */
    @Pattern(regexp = "0[1-4]", message = "payshield.default-pad-mode must be 01-04")
    private String defaultPadMode = "01";

    // ===== Key Block LMK specific defaults =====

    /**
     * Mode of Use for key block operations (EO, EY).
     * 'S' = Sign only (Key Type 0)
     * 'D' = Decrypt/unwrap only (Key Type 1)
     * 'N' = No restriction (Key Type 2 & 4)
     * Note: EI does NOT use this — EI auto-assigns Mode of Use from Key Type Indicator.
     */
    @Pattern(regexp = "[SDN]", message = "payshield.key-block-mode-of-use must be S, D, or N")
    private String keyBlockModeOfUse = "S";

    /** Key Version Number for key block header (00-99) */
    @Pattern(regexp = "[0-9]{2}", message = "payshield.key-block-key-version must be two digits (00-99)")
    private String keyBlockKeyVersion = "00";

    /** Exportability for key block: 'N' = Non-exportable, 'S' = Exportable under KEK */
    @Pattern(regexp = "[NS]", message = "payshield.key-block-exportability must be N or S")
    private String keyBlockExportability = "N";

    // --- Getters and Setters ---

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public int getPort() { return port; }
    public void setPort(int port) { this.port = port; }

    public int getPortKeyBlock() { return portKeyBlock; }
    public void setPortKeyBlock(int portKeyBlock) { this.portKeyBlock = portKeyBlock; }

    public String getLmkMode() { return lmkMode; }
    public void setLmkMode(String lmkMode) { this.lmkMode = lmkMode; }

    public String getLmkId() { return lmkId; }
    public void setLmkId(String lmkId) { this.lmkId = lmkId; }

    /**
     * Returns the LMK Identifier to embed in host commands, or null/blank to omit.
     */
    public String getResolvedLmkId() {
        if (lmkId == null || lmkId.isBlank()) {
            return null;
        }
        return lmkId;
    }

    /**
     * Returns the resolved LmkMode enum.
     */
    public LmkMode getResolvedLmkMode() {
        return LmkMode.fromValue(lmkMode);
    }

    /**
     * Returns the active HSM port based on the configured LMK mode.
     */
    public int getActivePort() {
        return getResolvedLmkMode() == LmkMode.KEYBLOCK ? portKeyBlock : port;
    }

    public int getHeaderLength() { return headerLength; }
    public void setHeaderLength(int headerLength) { this.headerLength = headerLength; }

    public int getConnectTimeoutMs() { return connectTimeoutMs; }
    public void setConnectTimeoutMs(int connectTimeoutMs) { this.connectTimeoutMs = connectTimeoutMs; }

    public int getReadTimeoutMs() { return readTimeoutMs; }
    public void setReadTimeoutMs(int readTimeoutMs) { this.readTimeoutMs = readTimeoutMs; }

    public boolean isLengthPrefixEnabled() { return lengthPrefixEnabled; }
    public void setLengthPrefixEnabled(boolean lengthPrefixEnabled) { this.lengthPrefixEnabled = lengthPrefixEnabled; }

    public int getPoolMaxTotal() { return poolMaxTotal; }
    public void setPoolMaxTotal(int poolMaxTotal) { this.poolMaxTotal = poolMaxTotal; }

    public int getPoolMaxIdle() { return poolMaxIdle; }
    public void setPoolMaxIdle(int poolMaxIdle) { this.poolMaxIdle = poolMaxIdle; }

    public int getPoolMinIdle() { return poolMinIdle; }
    public void setPoolMinIdle(int poolMinIdle) { this.poolMinIdle = poolMinIdle; }

    public long getPoolBorrowTimeoutMs() { return poolBorrowTimeoutMs; }
    public void setPoolBorrowTimeoutMs(long poolBorrowTimeoutMs) { this.poolBorrowTimeoutMs = poolBorrowTimeoutMs; }

    public String getPrivateKeyStorageIndex() { return privateKeyStorageIndex; }
    public void setPrivateKeyStorageIndex(String privateKeyStorageIndex) { this.privateKeyStorageIndex = privateKeyStorageIndex; }

    public int getDefaultModulusLength() { return defaultModulusLength; }
    public void setDefaultModulusLength(int defaultModulusLength) { this.defaultModulusLength = defaultModulusLength; }

    public String getDefaultHashId() { return defaultHashId; }
    public void setDefaultHashId(String defaultHashId) { this.defaultHashId = defaultHashId; }

    public String getDefaultSigId() { return defaultSigId; }
    public void setDefaultSigId(String defaultSigId) { this.defaultSigId = defaultSigId; }

    public String getDefaultPadMode() { return defaultPadMode; }
    public void setDefaultPadMode(String defaultPadMode) { this.defaultPadMode = defaultPadMode; }

    public String getKeyBlockModeOfUse() { return keyBlockModeOfUse; }
    public void setKeyBlockModeOfUse(String keyBlockModeOfUse) { this.keyBlockModeOfUse = keyBlockModeOfUse; }

    public String getKeyBlockKeyVersion() { return keyBlockKeyVersion; }
    public void setKeyBlockKeyVersion(String keyBlockKeyVersion) { this.keyBlockKeyVersion = keyBlockKeyVersion; }

    public String getKeyBlockExportability() { return keyBlockExportability; }
    public void setKeyBlockExportability(String keyBlockExportability) { this.keyBlockExportability = keyBlockExportability; }
}