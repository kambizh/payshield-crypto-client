package my.com.kambiz.hsm.command;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Utility methods for constructing payShield 10K host commands.
 * 
 * payShield wire format:
 * [header (configurable 0/2/4 ASCII chars)] [2-char command code] [command-specific fields]
 * 
 * Binary data is sent as raw bytes; ASCII fields are plain ASCII.
 * Lengths like "0009" are 4-digit zero-padded decimal ASCII strings.
 * Hex data in angle brackets in the docs is raw binary on the wire.
 */
public class CommandUtils {

    private CommandUtils() {}

    /** Generate a message header (zero-padded integer, e.g., "0310") */
    public static String generateHeader(int headerLength) {
        if (headerLength == 0) return "";
        // Use a counter or fixed header; for POC we use "0000"
        return String.format("%0" + headerLength + "d", 0);
    }

    /** Format a 4-digit zero-padded decimal length */
    public static String formatLength4(int length) {
        return String.format("%04d", length);
    }

    /** Convert hex string to byte array */
    public static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        if (hex.length() % 2 != 0) {
            hex = "0" + hex;
        }
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
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
