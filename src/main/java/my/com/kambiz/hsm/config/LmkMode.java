package my.com.kambiz.hsm.config;

/**
 * LMK operating mode for the payShield 10K.
 *
 * VARIANT  — 3DES Variant LMK (Lab port 1501). Legacy mode, PCI phase-out.
 *            Private keys encrypted under LMK pair 34-35 in raw blob format.
 *            Private key length field = actual byte length (4-digit decimal).
 *
 * KEYBLOCK — AES Key Block LMK (Lab port 1502). TR-31 compliant.
 *            Private keys in key block format, prefixed with 'S'.
 *            Private key length field = "FFFF" (reserved).
 *            EI command requires '#' delimiter + key block attributes.
 *            EW command with inline key uses 'S'-prefixed blob, length "FFFF".
 *            EW command with user storage uses "SK{index}" reference.
 */
public enum LmkMode {

    VARIANT("variant"),
    KEYBLOCK("keyblock");

    private final String value;

    LmkMode(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static LmkMode fromValue(String value) {
        for (LmkMode mode : values()) {
            if (mode.value.equalsIgnoreCase(value)) {
                return mode;
            }
        }
        throw new IllegalArgumentException(
                "Invalid LMK mode: '" + value + "'. Must be 'variant' or 'keyblock'.");
    }
}