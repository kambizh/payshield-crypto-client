package my.com.kambiz.hsm.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

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
@ConfigurationProperties(prefix = "payshield")
public class PayShieldProperties {

    /** HSM host IP address */
    private String host = "127.0.0.1";

    /** HSM host command port for Variant LMK (typically 1501) */
    private int port = 1501;

    /** HSM host command port for AES Key Block LMK (typically 1502) */
    private int portKeyBlock = 1502;

    /**
     * LMK operating mode: "variant" or "keyblock".
     * Controls which port is used and how commands are constructed/parsed.
     */
    private String lmkMode = "variant";

    /** Message header length configured on the HSM (0, 2, or 4 chars) */
    private int headerLength = 4;

    /** Connection timeout in milliseconds */
    private int connectTimeoutMs = 5000;

    /** Read/response timeout in milliseconds */
    private int readTimeoutMs = 10000;

    /** Whether to use 2-byte length prefix framing on TCP */
    private boolean lengthPrefixEnabled = true;

    /** Connection pool: max total connections */
    private int poolMaxTotal = 5;

    /** Connection pool: max idle connections */
    private int poolMaxIdle = 3;

    /** Connection pool: min idle connections */
    private int poolMinIdle = 1;

    /** User storage index for RSA private key (000-FFF) */
    private String privateKeyStorageIndex = "000";

    /** Default RSA modulus length in bits */
    private int defaultModulusLength = 2048;

    /** Hash algorithm ID: 01=SHA-1, 02=MD5, 03=ISO10118-2, 04=NoHash, 05=SHA-224, 06=SHA-256, 07=SHA-384, 08=SHA-512 */
    private String defaultHashId = "06";

    /** Signature algorithm ID: 01=RSA */
    private String defaultSigId = "01";

    /** Pad mode: 01=PKCS#1 v1.5, 02=ANSI X9.31, 03=ISO 9796, 04=PSS */
    private String defaultPadMode = "01";

    // ===== Key Block LMK specific defaults =====

    /**
     * Mode of Use for EI key block generation.
     * 'S' = Sign only (Key Type 0)
     * 'D' = Decrypt/unwrap only (Key Type 1)
     * 'N' = No restriction (Key Type 2 & 4)
     */
    private String keyBlockModeOfUse = "S";

    /** Key Version Number for key block header (00-99) */
    private String keyBlockKeyVersion = "00";

    /** Exportability for key block: 'N' = Non-exportable, 'S' = Exportable under KEK */
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