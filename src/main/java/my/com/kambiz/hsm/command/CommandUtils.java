package my.com.kambiz.hsm.command;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Utility methods for constructing payShield 10K host commands.
 * 
 * payShield wire format:
 * [header (configurable 0/2/4 ASCII chars)] [2-char command code] [command-specific fields]
 * 
 * Binary data is sent as raw bytes; ASCII fields are plain ASCII.
 * Lengths like "0009" are 4-digit zero-padded decimal ASCII strings.
 * Hex data in angle brackets in the docs is raw binary on the wire.
 *
 * Message Header:
 *   The header is an opaque echo tag — the HSM returns it unchanged in the response.
 *   It serves as a correlation ID for matching requests to responses in logs and audit trails.
 *   For concurrent operations, each request should have a unique header value.
 */
public class CommandUtils {

    private CommandUtils() {}

    /**
     * Thread-safe counter for auto-generated headers.
     * Wraps at the maximum value for the configured header length:
     *   2-char header → 00-99 (100 values)
     *   4-char header → 0000-9999 (10,000 values)
     *
     * The wrap-around is safe because headers are only for correlation/logging.
     * By the time a counter wraps, the previous request with the same header
     * has long since completed.
     */
    private static final AtomicInteger HEADER_COUNTER = new AtomicInteger(0);

    /**
     * Generate a unique message header for request correlation.
     * Thread-safe: uses an atomic counter that wraps at the header length limit.
     *
     * @param headerLength configured header length (0, 2, or 4)
     * @return unique header string (e.g., "0042", "1337")
     */
    public static String generateHeader(int headerLength) {
        if (headerLength == 0) return "";
        int maxValue = (int) Math.pow(10, headerLength); // 100 for 2-char, 10000 for 4-char
        int value = HEADER_COUNTER.getAndUpdate(v -> (v + 1) % maxValue);
        return String.format("%0" + headerLength + "d", value);
    }

    /**
     * Format a caller-provided correlation ID as a message header.
     * Truncates or pads to fit the configured header length.
     *
     * Use this when iMochaRPPGateway wants to embed its own transaction ID
     * (or part of it) into the HSM header for end-to-end traceability.
     *
     * @param correlationId caller's correlation/transaction ID
     * @param headerLength  configured header length (0, 2, or 4)
     * @return formatted header string
     */
    public static String formatHeader(String correlationId, int headerLength) {
        if (headerLength == 0) return "";
        if (correlationId == null || correlationId.isEmpty()) {
            return generateHeader(headerLength);
        }
        // Take the last N characters (most unique part of a correlation ID)
        String id = correlationId.replaceAll("[^A-Za-z0-9]", "");
        if (id.length() >= headerLength) {
            return id.substring(id.length() - headerLength);
        }
        // Pad with leading zeros
        return String.format("%" + headerLength + "s", id).replace(' ', '0');
    }

    /** Format a 4-digit zero-padded decimal length */
    public static String formatLength4(int length) {
        return String.format("%04d", length);
    }

    /**
     * Convert a hex string to a byte array, with strict validation.
     *
     * Whitespace (spaces, tabs, newlines) is stripped for convenience, but the
     * remaining input must be well-formed: an even number of characters and only
     * hex digits. Malformed input throws {@link IllegalArgumentException} rather than
     * being silently padded or partially parsed — this matters for cryptographic
     * material, where a mangled byte sequence must never be accepted.
     *
     * @throws IllegalArgumentException if the input is null/empty, has an odd length,
     *                                  or contains a non-hex character
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex input must not be null");
        }
        String cleaned = hex.replaceAll("\\s+", "");
        if (cleaned.isEmpty()) {
            throw new IllegalArgumentException("hex input must not be empty");
        }
        if (cleaned.length() % 2 != 0) {
            throw new IllegalArgumentException(
                    "hex input must have an even number of digits (got " + cleaned.length() + ")");
        }
        byte[] bytes = new byte[cleaned.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int hi = Character.digit(cleaned.charAt(i * 2), 16);
            int lo = Character.digit(cleaned.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                int badPos = hi < 0 ? i * 2 : i * 2 + 1;
                throw new IllegalArgumentException(
                        "hex input contains a non-hex character at position " + badPos);
            }
            bytes[i] = (byte) ((hi << 4) | lo);
        }
        return bytes;
    }

    /** Convert byte array to hex string (uppercase) */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Build a complete command as a byte array.
     * Concatenates header + command code + payload parts.
     */
    public static byte[] buildCommand(String header, String commandCode, Object... parts) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(512);
            // Header (ASCII)
            if (header != null && !header.isEmpty()) {
                bos.write(header.getBytes(StandardCharsets.US_ASCII));
            }
            // Command code (ASCII)
            bos.write(commandCode.getBytes(StandardCharsets.US_ASCII));
            // Remaining parts
            for (Object part : parts) {
                if (part instanceof byte[] bytes) {
                    bos.write(bytes);
                } else if (part instanceof String s) {
                    bos.write(s.getBytes(StandardCharsets.US_ASCII));
                }
            }
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Error building command", e);
        }
    }

    /**
     * Append an optional LMK Identifier trailer for shared-port multi-LMK hosts.
     * When {@code lmkId} is blank/null, returns {@code command} unchanged.
     * When set (e.g. "00" or "01"), appends ASCII "%{lmkId}" to the end of the command.
     *
     * Used by commands that do not embed '%' inside a mid-command '#' section
     * (e.g. EW). EI embeds "%{id}" before '#' itself and should not use this helper.
     *
     * Example (Key Block EW):
     *   ... ; 99 FFFF [S-keyblock] %01
     */
    public static byte[] withLmkId(byte[] command, String lmkId) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        if (lmkId == null || lmkId.isBlank()) {
            return command;
        }
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(command.length + 1 + lmkId.length());
            bos.write(command);
            bos.write('%');
            bos.write(lmkId.getBytes(StandardCharsets.US_ASCII));
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Error appending LMK id", e);
        }
    }

    /**
     * Parse the header from a response (first N bytes as ASCII).
     */
    public static String extractHeader(byte[] response, int headerLength) {
        if (headerLength == 0 || response.length < headerLength) return "";
        return new String(response, 0, headerLength, StandardCharsets.US_ASCII);
    }

    /**
     * Parse the 2-char response code (immediately after header).
     */
    public static String extractResponseCode(byte[] response, int headerLength) {
        int offset = headerLength;
        if (response.length < offset + 2) return "??";
        return new String(response, offset, 2, StandardCharsets.US_ASCII);
    }

    /**
     * Parse the 2-char error code (immediately after response code).
     */
    public static String extractErrorCode(byte[] response, int headerLength) {
        int offset = headerLength + 2;
        if (response.length < offset + 2) return "??";
        return new String(response, offset, 2, StandardCharsets.US_ASCII);
    }

    /**
     * Extract payload bytes after header + response code + error code.
     */
    public static byte[] extractPayload(byte[] response, int headerLength) {
        int offset = headerLength + 4; // 2 (resp code) + 2 (error code)
        if (response.length <= offset) return new byte[0];
        byte[] payload = new byte[response.length - offset];
        System.arraycopy(response, offset, payload, 0, payload.length);
        return payload;
    }

    /**
     * Decode hash algorithm ID to human-readable name.
     */
    public static String decodeHashAlgorithm(String hashId) {
        return switch (hashId) {
            case "01" -> "SHA-1";
            case "02" -> "MD5";
            case "03" -> "ISO 10118-2";
            case "04" -> "No Hash (raw data)";
            case "05" -> "SHA-224";
            case "06" -> "SHA-256";
            case "07" -> "SHA-384";
            case "08" -> "SHA-512";
            default -> "Unknown (" + hashId + ")";
        };
    }

    /**
     * Decode pad mode ID to human-readable name.
     */
    public static String decodePadMode(String padMode) {
        return switch (padMode) {
            case "01" -> "PKCS#1 v1.5";
            case "02" -> "ANSI X9.31";
            case "03" -> "ISO 9796";
            case "04" -> "PSS";
            default -> "Unknown (" + padMode + ")";
        };
    }
}