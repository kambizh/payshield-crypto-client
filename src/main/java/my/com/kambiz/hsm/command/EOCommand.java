package my.com.kambiz.hsm.command;

import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.PublicKeyImportResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * EO Command - Import a Public Key
 * 
 * Generates a MAC over the public key + authentication data using LMK pair 36-37.
 * This MAC is required for the EY (verify signature) command.
 * 
 * Command format:
 *   [Header] EO [EncodingRules:2N] [PublicKey:DER] [AuthData:optional]
 * 
 * Response (EP):
 *   [Header] EP [ErrorCode:2A] [MAC:4bytes] [PublicKey:DER]
 */
public class EOCommand {

    private static final Logger log = LoggerFactory.getLogger(EOCommand.class);

    private EOCommand() {}

    /**
     * Build EO command to import a public key and get its MAC.
     * 
     * @param header         message header
     * @param publicKeyDer   DER-encoded RSA public key
     * @param authData       optional authentication data (can be empty byte array)
     */
    public static byte[] build(String header, byte[] publicKeyDer, byte[] authData) {
        return CommandUtils.buildCommand(header, "EO",
                "01",               // Encoding rules: 01 = DER ASN.1
                publicKeyDer,       // Public key in DER format
                authData != null ? authData : new byte[0]  // Optional auth data
        );
    }

    /**
     * Parse the EP response.
     * Payload after header + "EP" + "00":
     *   [MAC:4 bytes] [PublicKey:DER encoded, variable length]
     */
    public static PublicKeyImportResult parseResponse(byte[] response, int headerLength) {
        String respCode = CommandUtils.extractResponseCode(response, headerLength);
        String errCode = CommandUtils.extractErrorCode(response, headerLength);

        if (!"EP".equals(respCode)) {
            throw new PayShieldException("EO", respCode,
                    "Unexpected response code (expected EP, got " + respCode + ")");
        }

        if (!"00".equals(errCode)) {
            throw new PayShieldException("EO", errCode,
                    PayShieldException.decodeErrorCode(errCode));
        }

        int offset = headerLength + 4; // header + "EP" + "00"
        byte[] payload = new byte[response.length - offset];
        System.arraycopy(response, offset, payload, 0, payload.length);

        // First 4 bytes = MAC
        byte[] mac = new byte[4];
        System.arraycopy(payload, 0, mac, 0, 4);

        // Rest = public key DER
        byte[] pubKeyDer = new byte[payload.length - 4];
        System.arraycopy(payload, 4, pubKeyDer, 0, pubKeyDer.length);

        log.info("EO response parsed: MAC={}, pubKey={} bytes",
                CommandUtils.bytesToHex(mac), pubKeyDer.length);

        return new PublicKeyImportResult(mac, pubKeyDer);
    }
}
