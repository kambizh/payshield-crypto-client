package my.com.kambiz.hsm.command;

import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.CsrGenerationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * QE Command - Generate a Certificate Signing Request (CSR)
 *
 * Generates a PKCS#10 CSR by signing the Subject and Public Key information
 * with the corresponding Private Key. Key Block LMK only.
 *
 * Command format (Subject Data Type = '1', specify individual fields):
 *   [Header] QE
 *   [CSR Type: 1N]            '0' = PKCS#10
 *   [CSR Output Format: 1N]   '0' = Base64 PEM, '1' = Hex DER
 *   [Signature ID: 2N]        '01' = RSA
 *   [Public Key Encoding: 2N] '01' = DER unsigned
 *   [Public Key: n B]         DER-encoded public key
 *   [Private Key: 'S'+n A]    S-prefixed Key Block private key
 *   [Pad Mode: 2N]            '01' = PKCS#1 v1.5, '04' = PSS
 *   [Hash ID: 2N]             '06' = SHA-256
 *   [Subject Data Type: 1N]   '1' = specify fields
 *   [Common Name] ;
 *   [Organization] ;
 *   [Organizational Unit] ;
 *   [Locality] ;
 *   [State] ;
 *   [Country: 2A] ;
 *
 * Command format (Subject Data Type = '0', DER template):
 *   ... same up to Hash ID ...
 *   [Subject Data Type: 1N]       '0' = use template
 *   [Subject Template Length: 4N] length of DER template
 *   [Subject Template: n H]       ASN.1 DER encoded Subject
 *   ;
 *
 * Response (QF):
 *   [Header] QF [Error: 2A] [CSR Length: 4N] [CSR: n A or n H]
 *
 * Error codes:
 *   00 = No error
 *   E0 = Invalid CSR type
 *   E1 = Invalid CSR output format
 *   E2 = Invalid public key format
 *   E3 = Public key block error (+ 2-char additional error code)
 *   E4 = Invalid public key
 *   E5 = Private key block error (+ 2-char additional error code)
 *   E7 = Invalid subject data type
 *   E8 = Subject data is not valid DER encoding
 *   E9 = CSR attribute SET OF field missing after '=' delimiter
 */
public class QECommand {

    private static final Logger log = LoggerFactory.getLogger(QECommand.class);

    private QECommand() {}

    // ===== BUILD (Subject Data Type = '1', individual fields) =====

    /**
     * Build QE command with individual subject fields.
     *
     * @param header         message header (e.g. "0000")
     * @param publicKeyDer   DER-encoded RSA public key from EI
     * @param privateKeyBlock S-prefixed Key Block private key from EI
     * @param hashId         hash algorithm: "06"=SHA-256, "07"=SHA-384, "08"=SHA-512
     * @param padMode        pad mode: "01"=PKCS#1 v1.5, "04"=PSS
     * @param outputFormat   "0"=PEM (Base64), "1"=Hex DER
     * @param commonName     CN (1-64 chars)
     * @param organization   O (1-64 chars)
     * @param orgUnit        OU (1-64 chars)
     * @param locality       L (1-64 chars)
     * @param state          ST (1-64 chars)
     * @param country        C (2-char ISO code, e.g. "MY")
     */
    public static byte[] build(String header,
                               byte[] publicKeyDer, byte[] privateKeyBlock,
                               String hashId, String padMode, String outputFormat,
                               String commonName, String organization, String orgUnit,
                               String locality, String state, String country) {

        log.info("Building QE command: CN={}, O={}, OU={}, L={}, ST={}, C={}, hash={}, pad={}, format={}",
                commonName, organization, orgUnit, locality, state, country,
                hashId, padMode, outputFormat.equals("0") ? "PEM" : "HexDER");

        return CommandUtils.buildCommand(header, "QE",
                "0",                    // CSR Type: PKCS#10
                outputFormat,           // CSR Output Format: 0=PEM, 1=Hex DER
                "01",                   // Signature ID: RSA
                "01",                   // Public Key Encoding: DER unsigned
                publicKeyDer,           // Public Key (binary DER)
                privateKeyBlock,        // Private Key (S-prefixed Key Block — sent as ASCII)
                padMode,                // Pad Mode: 01=PKCS#1 v1.5
                hashId,                 // Hash ID: 06=SHA-256
                "1",                    // Subject Data Type: 1=specify fields
                commonName, ";",
                organization, ";",
                orgUnit, ";",
                locality, ";",
                state, ";",
                country, ";"
        );
    }

    /**
     * Build QE command with PEM output and SHA-256 / PKCS#1 v1.5 defaults.
     */
    public static byte[] buildPem(String header,
                                  byte[] publicKeyDer, byte[] privateKeyBlock,
                                  String commonName, String organization, String orgUnit,
                                  String locality, String state, String country) {
        return build(header, publicKeyDer, privateKeyBlock,
                "06", "01", "0",
                commonName, organization, orgUnit, locality, state, country);
    }

    /**
     * Build QE command with DER hex output.
     */
    public static byte[] buildDer(String header,
                                  byte[] publicKeyDer, byte[] privateKeyBlock,
                                  String commonName, String organization, String orgUnit,
                                  String locality, String state, String country) {
        return build(header, publicKeyDer, privateKeyBlock,
                "06", "01", "1",
                commonName, organization, orgUnit, locality, state, country);
    }

    // ===== BUILD (Subject Data Type = '0', DER template) =====

    /**
     * Build QE command with a pre-built DER-encoded subject template.
     * Use this when you need full control over the subject DN encoding
     * (e.g. specific OID ordering, custom attributes).
     *
     * @param header              message header
     * @param publicKeyDer        DER-encoded RSA public key
     * @param privateKeyBlock     S-prefixed Key Block private key
     * @param hashId              hash algorithm
     * @param padMode             pad mode
     * @param outputFormat        "0"=PEM, "1"=Hex DER
     * @param subjectTemplateDer  ASN.1 DER encoded Subject (hex string)
     */
    public static byte[] buildWithTemplate(String header,
                                           byte[] publicKeyDer, byte[] privateKeyBlock,
                                           String hashId, String padMode, String outputFormat,
                                           String subjectTemplateDer) {

        String templateLength = CommandUtils.formatLength4(subjectTemplateDer.length() / 2);

        log.info("Building QE command with DER template: templateLen={}, hash={}, pad={}",
                templateLength, hashId, padMode);

        return CommandUtils.buildCommand(header, "QE",
                "0",                    // CSR Type: PKCS#10
                outputFormat,           // CSR Output Format
                "01",                   // Signature ID: RSA
                "01",                   // Public Key Encoding: DER unsigned
                publicKeyDer,           // Public Key (binary DER)
                privateKeyBlock,        // Private Key (S-prefixed Key Block)
                padMode,                // Pad Mode
                hashId,                 // Hash ID
                "0",                    // Subject Data Type: 0=use template
                templateLength,         // Subject Template Length (4N, byte count)
                subjectTemplateDer,     // Subject Template (hex DER)
                ";"                     // Delimiter
        );
    }

    // ===== PARSE =====

    /**
     * Parse the QF response into a CsrGenerationResult.
     *
     * Response payload after header + "QF" + "00":
     *   [CSR Length: 4N] [CSR: n A (PEM) or n H (Hex DER)]
     *
     * Error codes E3/E5 have an additional 2-char error code.
     */
    public static CsrGenerationResult parseResponse(byte[] response, int headerLength) {
        String respCode = CommandUtils.extractResponseCode(response, headerLength);
        String errCode = CommandUtils.extractErrorCode(response, headerLength);

        if (!"QF".equals(respCode)) {
            throw new PayShieldException("QE", respCode,
                    "Unexpected response code (expected QF, got " + respCode + ")");
        }

        if (!"00".equals(errCode)) {
            // Check for extended error codes (E3, E5 have additional 2-char code)
            String detail = "";
            if (("E3".equals(errCode) || "E5".equals(errCode)) && response.length > headerLength + 6) {
                detail = " [additional: " + new String(response, headerLength + 4, 2, StandardCharsets.US_ASCII) + "]";
            }
            throw new PayShieldException("QE", errCode,
                    decodeQEErrorCode(errCode) + detail);
        }

        int offset = headerLength + 4; // header + "QF" + "00"

        // 4-digit decimal CSR length
        String csrLenStr = new String(response, offset, 4, StandardCharsets.US_ASCII);
        int csrLen = Integer.parseInt(csrLenStr);
        offset += 4;

        // CSR data (PEM string or hex DER)
        String csrData = new String(response, offset, csrLen, StandardCharsets.US_ASCII);

        log.info("QE response parsed: CSR length={} chars", csrLen);

        return new CsrGenerationResult(csrData, csrLen);
    }

    /**
     * Decode QE-specific error codes.
     */
    private static String decodeQEErrorCode(String errorCode) {
        return switch (errorCode) {
            case "00" -> "No error";
            case "05" -> "Invalid hash identifier";
            case "07" -> "Invalid pad mode identifier";
            case "D2" -> "Invalid curve reference value";
            case "E0" -> "Invalid CSR type value";
            case "E1" -> "Invalid CSR output format";
            case "E2" -> "Invalid public key format value";
            case "E3" -> "Public key block error";
            case "E4" -> "Invalid public key";
            case "E5" -> "Private key block error";
            case "E6" -> "Invalid MGF function";
            case "E7" -> "Invalid subject data type";
            case "E8" -> "Subject data is not valid DER encoding";
            case "E9" -> "CSR attribute SET OF field missing after '=' delimiter";
            default -> PayShieldException.decodeErrorCode(errorCode);
        };
    }
}