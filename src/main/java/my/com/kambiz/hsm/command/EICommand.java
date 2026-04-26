package my.com.kambiz.hsm.command;

import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.KeyGenerationResult;
import my.com.kambiz.hsm.model.PayShieldResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * EI Command - Generate RSA Key Pair
 * 
 * Command format:
 *   [Header] EI [KeyType:1N] [ModulusLength:4N] [EncodingRules:2N]
 * 
 * Response (EJ):
 *   [Header] EJ [ErrorCode:2A] [PublicKey:variable DER] [PrivKeyLength:4N] [PrivKey:variable LMK-encrypted]
 * 
 * KeyType: 0=key management, 1=signature generation+verification
 * EncodingRules: 01=DER encoding for ASN.1 Public Key
 */
public class EICommand {

    private static final Logger log = LoggerFactory.getLogger(EICommand.class);

    private EICommand() {}

    /**
     * Build the EI command bytes.
     * 
     * @param header     message header string (e.g. "0000")
     * @param keyType    0 or 1 (1 = signature gen + verify)
     * @param modulusBits RSA modulus length: 320-4096
     * @param encoding   01 = DER ASN.1
     */
    public static byte[] build(String header, int keyType, int modulusBits, String encoding) {
        return CommandUtils.buildCommand(header, "EI",
                String.valueOf(keyType),                          // Key type indicator
                String.format("%04d", modulusBits),               // Modulus length
                encoding                                          // Encoding rules (01 = DER)
        );
    }

    /**
     * Parse the EJ response into a KeyGenerationResult.
     * 
     * EJ response payload after header + "EJ" + "00":
     *   [PublicKey DER bytes][PrivKeyLength 4-digit decimal][PrivKey LMK-encrypted bytes]
     * 
     * The public key is DER-encoded and starts with 0x30 (SEQUENCE tag).
     * We need to parse the DER to determine where it ends, then read the private key length.
     */
    public static KeyGenerationResult parseResponse(byte[] response, int headerLength, int modulusBits) {
        String respCode = CommandUtils.extractResponseCode(response, headerLength);
        String errCode = CommandUtils.extractErrorCode(response, headerLength);

        if (!"EJ".equals(respCode)) {
            throw new PayShieldException("EI", respCode,
                    "Unexpected response code (expected EJ, got " + respCode + ")");
        }

        if (!"00".equals(errCode)) {
            throw new PayShieldException("EI", errCode,
                    PayShieldException.decodeErrorCode(errCode));
        }

        // Payload starts after header + "EJ" + "00"
        int offset = headerLength + 4;
        byte[] payload = new byte[response.length - offset];
        System.arraycopy(response, offset, payload, 0, payload.length);

        // The public key is DER-encoded starting with 0x30 (SEQUENCE).
        // Parse the DER length to find where the public key ends.
        int pubKeyLen = parseDerLength(payload, 0);
        byte[] publicKeyDer = new byte[pubKeyLen];
        System.arraycopy(payload, 0, publicKeyDer, 0, pubKeyLen);

        // After the public key: 4-digit decimal private key length
        int privLenOffset = pubKeyLen;
        String privLenStr = new String(payload, privLenOffset, 4, StandardCharsets.US_ASCII);
        int privKeyLen = Integer.parseInt(privLenStr);

        // After that: the LMK-encrypted private key
        int privKeyOffset = privLenOffset + 4;
        byte[] privateKey = new byte[privKeyLen];
        System.arraycopy(payload, privKeyOffset, privateKey, 0, privKeyLen);

        log.info("EI response parsed: pubKey={} bytes, privKey={} bytes (LMK-encrypted), modulus={} bits",
                pubKeyLen, privKeyLen, modulusBits);

        return new KeyGenerationResult(publicKeyDer, privateKey, privKeyLen, modulusBits);
    }

    /**
     * Parse a DER-encoded structure to determine its total length (tag + length + content).
     * Handles both short-form and long-form length encoding.
     */
    private static int parseDerLength(byte[] data, int startOffset) {
        if (data.length <= startOffset + 1) {
            throw new PayShieldException("DER data too short to parse");
        }

        // Skip the tag byte (0x30 for SEQUENCE)
        int offset = startOffset + 1;

        int firstByte = data[offset] & 0xFF;
        offset++;

        int contentLength;
        if (firstByte < 0x80) {
            // Short form: length is the byte itself
            contentLength = firstByte;
        } else {
            // Long form: firstByte & 0x7F = number of subsequent bytes encoding the length
            int numLenBytes = firstByte & 0x7F;
            contentLength = 0;
            for (int i = 0; i < numLenBytes; i++) {
                contentLength = (contentLength << 8) | (data[offset] & 0xFF);
                offset++;
            }
        }

        // Total = header bytes consumed + content length
        int totalLength = (offset - startOffset) + contentLength;

        log.debug("DER total length from offset {}: {} bytes (content: {} bytes)", startOffset, totalLength, contentLength);
        return totalLength;
    }
}
