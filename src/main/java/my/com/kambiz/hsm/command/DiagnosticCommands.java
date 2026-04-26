package my.com.kambiz.hsm.command;

import my.com.kambiz.hsm.exception.PayShieldException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Diagnostic commands for payShield 10K.
 * These do NOT require authorization — perfect for connection testing.
 *
 * NC Command - Perform Diagnostics (response: ND)
 *   Tests processor, software, LMK. Returns LMK check value + firmware number.
 *   Command:  [Header] NC
 *   Response: [Header] ND [ErrorCode:2A] [LMKCheck:16N] [FirmwareNumber:9A]
 *
 * NO Command - HSM Status (response: NP)
 *   Returns HSM status information.
 *   Command:  [Header] NO [ModeFlag:2H]
 *   Response: [Header] NP [ErrorCode:2A] [IOBufferSize:1N] [EthernetType:1N]
 *             [NumTCPSockets:2N] [FirmwareNumber:9A] [Reserved:1N] [Reserved:4A]
 */
public class DiagnosticCommands {

    private static final Logger log = LoggerFactory.getLogger(DiagnosticCommands.class);

    private DiagnosticCommands() {}

    // ===== NC - Perform Diagnostics =====

    /**
     * Build NC command (Perform Diagnostics).
     * No authorization required.
     */
    public static byte[] buildNC(String header) {
        return CommandUtils.buildCommand(header, "NC");
    }

    /**
     * Parse ND response.
     * Returns map with: errorCode, lmkCheckValue, firmwareNumber
     */
    public static Map<String, String> parseNCResponse(byte[] response, int headerLength) {
        String respCode = CommandUtils.extractResponseCode(response, headerLength);
        String errCode = CommandUtils.extractErrorCode(response, headerLength);

        Map<String, String> result = new LinkedHashMap<>();
        result.put("command", "NC (Perform Diagnostics)");
        result.put("responseCode", respCode);
        result.put("errorCode", errCode);
        result.put("errorDescription", PayShieldException.decodeErrorCode(errCode));
        result.put("rawResponseHex", CommandUtils.bytesToHex(response));

        if (!"ND".equals(respCode)) {
            result.put("status", "ERROR");
            result.put("detail", "Unexpected response code: " + respCode + " (expected ND)");
            return result;
        }

        if ("00".equals(errCode)) {
            int offset = headerLength + 4; // header + "ND" + "00"
            byte[] payload = new byte[response.length - offset];
            System.arraycopy(response, offset, payload, 0, payload.length);
            String payloadStr = new String(payload, StandardCharsets.US_ASCII);

            // LMK check value: 16N, Firmware number: 9A
            if (payloadStr.length() >= 25) {
                result.put("lmkCheckValue", payloadStr.substring(0, 16));
                result.put("firmwareNumber", payloadStr.substring(16, 25));
            } else {
                result.put("payloadRaw", payloadStr);
            }
            result.put("status", "OK");
        } else {
            result.put("status", "ERROR");
        }

        log.info("NC response: {}", result);
        return result;
    }

    // ===== NO - HSM Status =====

    /**
     * Build NO command (HSM Status).
     * No authorization required.
     *
     * @param header    message header
     * @param modeFlag  "00" = status info, "01" = PCI HSM compliance
     */
    public static byte[] buildNO(String header, String modeFlag) {
        return CommandUtils.buildCommand(header, "NO", modeFlag);
    }

    /**
     * Parse NP response (HSM Status, mode 00).
     * Returns map with status fields.
     */
    public static Map<String, String> parseNOResponse(byte[] response, int headerLength) {
        String respCode = CommandUtils.extractResponseCode(response, headerLength);
        String errCode = CommandUtils.extractErrorCode(response, headerLength);

        Map<String, String> result = new LinkedHashMap<>();
        result.put("command", "NO (HSM Status)");
        result.put("responseCode", respCode);
        result.put("errorCode", errCode);
        result.put("errorDescription", PayShieldException.decodeErrorCode(errCode));
        result.put("rawResponseHex", CommandUtils.bytesToHex(response));

        if (!"NP".equals(respCode)) {
            result.put("status", "ERROR");
            result.put("detail", "Unexpected response code: " + respCode + " (expected NP)");
            return result;
        }

        if ("00".equals(errCode)) {
            int offset = headerLength + 4; // header + "NP" + "00"
            byte[] payload = new byte[response.length - offset];
            System.arraycopy(response, offset, payload, 0, payload.length);
            String payloadStr = new String(payload, StandardCharsets.US_ASCII);

            // Mode 00 response: IOBufSize(1) + EthType(1) + NumSockets(2) + Firmware(9) + Reserved(5)
            if (payloadStr.length() >= 13) {
                String ioBuf = payloadStr.substring(0, 1);
                result.put("ioBufferSize", switch (ioBuf) {
                    case "0" -> "2K bytes";
                    case "1" -> "8K bytes";
                    case "2" -> "16K bytes";
                    case "3" -> "32K bytes";
                    default -> ioBuf + " (unknown)";
                });
                String ethType = payloadStr.substring(1, 2);
                result.put("ethernetType", "0".equals(ethType) ? "UDP" : "TCP");
                result.put("numTcpSockets", payloadStr.substring(2, 4));
                result.put("firmwareNumber", payloadStr.substring(4, 13));
                if (payloadStr.length() > 13) {
                    result.put("reserved", payloadStr.substring(13));
                }
            } else {
                result.put("payloadRaw", payloadStr);
            }
            result.put("status", "OK");
        } else {
            result.put("status", "ERROR");
        }

        log.info("NO response: {}", result);
        return result;
    }
}