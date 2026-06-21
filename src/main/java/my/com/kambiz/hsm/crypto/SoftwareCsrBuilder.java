package my.com.kambiz.hsm.crypto;

import my.com.kambiz.hsm.command.CommandUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Builds a PKCS#10 CSR (Certificate Signing Request) entirely in software.
 *
 * Used when the HSM is in Variant LMK mode, because the native QE command
 * is Key Block LMK only (requires an S-prefixed TR-31 private key block).
 *
 * Approach — three steps, no external ASN.1 library needed:
 *   1. Build TbsCertificationRequest DER here (subject DN + public key + empty attributes)
 *   2. Sign the TBS via the HSM's EW command (works in both Variant and Key Block)
 *   3. Wrap TBS + AlgorithmIdentifier + BIT STRING into the final PKCS#10 SEQUENCE
 *
 * The private key never leaves the HSM in cleartext. EW receives the
 * LMK-encrypted key blob and performs the RSA signing inside the HSM boundary.
 *
 * Supported signature algorithm: SHA-256 with RSA (sha256WithRSAEncryption).
 */
public class SoftwareCsrBuilder {

    private static final Logger log = LoggerFactory.getLogger(SoftwareCsrBuilder.class);

    // OID 1.2.840.113549.1.1.11 — sha256WithRSAEncryption
    private static final byte[] OID_SHA256_WITH_RSA = {
        0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x0B
    };

    // X.500 attribute type OIDs
    private static final byte[] OID_CN = {0x55, 0x04, 0x03};
    private static final byte[] OID_O  = {0x55, 0x04, 0x0A};
    private static final byte[] OID_OU = {0x55, 0x04, 0x0B};
    private static final byte[] OID_L  = {0x55, 0x04, 0x07};
    private static final byte[] OID_ST = {0x55, 0x04, 0x08};
    private static final byte[] OID_C  = {0x55, 0x04, 0x06};

    private SoftwareCsrBuilder() {}

    // ===== PUBLIC API =====

    /**
     * Build the DER-encoded Subject Name (SEQUENCE OF RDN).
     * Field order: CN → O → OU → L → ST → C — matches the PayShield QE command.
     * Country is encoded as PrintableString per RFC 5280; all others as UTF8String.
     *
     * @param cn  Common Name
     * @param o   Organisation
     * @param ou  Organisational Unit
     * @param l   Locality
     * @param st  State/Province
     * @param c   Country (2-char ISO 3166-1 code)
     * @return DER-encoded Name
     */
    public static byte[] buildSubjectDer(String cn, String o, String ou,
                                          String l, String st, String c) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            if (notBlank(cn)) bos.write(rdn(OID_CN, utf8(cn)));
            if (notBlank(o))  bos.write(rdn(OID_O,  utf8(o)));
            if (notBlank(ou)) bos.write(rdn(OID_OU, utf8(ou)));
            if (notBlank(l))  bos.write(rdn(OID_L,  utf8(l)));
            if (notBlank(st)) bos.write(rdn(OID_ST, utf8(st)));
            if (notBlank(c))  bos.write(rdn(OID_C,  printable(c)));
            return derSequence(bos.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException("Failed to build Subject DER", e);
        }
    }

    /**
     * Build the DER-encoded TbsCertificationRequest.
     * This is the byte array that the HSM must sign (via EW).
     *
     *   TbsCertificationRequest ::= SEQUENCE {
     *     version    INTEGER { v1(0) } DEFAULT v1,
     *     subject    Name,
     *     subjectPKInfo SubjectPublicKeyInfo,
     *     attributes [0] IMPLICIT SET OF Attribute
     *   }
     *
     * @param subjectDer   output of buildSubjectDer()
     * @param publicKeyDer DER-encoded SubjectPublicKeyInfo from EI response
     * @return DER bytes of TbsCertificationRequest
     */
    public static byte[] buildTbs(byte[] subjectDer, byte[] publicKeyDer) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(derInteger(new byte[]{0x00}));      // version = v1(0)
            bos.write(subjectDer);                         // subject
            bos.write(publicKeyDer);                       // subjectPKInfo (already DER from HSM)
            bos.write(new byte[]{(byte)0xA0, 0x00});      // [0] empty attributes
            return derSequence(bos.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException("Failed to build TbsCertificationRequest", e);
        }
    }

    /**
     * Assemble the final PKCS#10 CertificationRequest DER from its parts.
     *
     *   CertificationRequest ::= SEQUENCE {
     *     certificationRequestInfo TbsCertificationRequest,
     *     signatureAlgorithm       AlgorithmIdentifier { sha256WithRSAEncryption },
     *     signature                BIT STRING
     *   }
     *
     * @param tbsDer    DER-encoded TbsCertificationRequest (from buildTbs)
     * @param signature Raw RSA signature bytes from the EW HSM command
     * @return DER-encoded PKCS#10 CertificationRequest
     */
    public static byte[] buildCsr(byte[] tbsDer, byte[] signature) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(tbsDer);
            bos.write(sha256WithRsaAlgId());
            bos.write(derBitString(signature));
            byte[] csr = derSequence(bos.toByteArray());
            log.debug("Built PKCS#10 CSR: {} bytes (TBS={}, sig={})",
                    csr.length, tbsDer.length, signature.length);
            return csr;
        } catch (IOException e) {
            throw new RuntimeException("Failed to build PKCS#10 CertificationRequest", e);
        }
    }

    /**
     * Encode DER bytes as a PEM CERTIFICATE REQUEST block with 64-char line wrapping.
     */
    public static String toPem(byte[] derBytes) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(derBytes);
        return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + b64
                + "\n-----END CERTIFICATE REQUEST-----\n";
    }

    /**
     * Encode DER bytes as an uppercase hex string.
     */
    public static String toHex(byte[] derBytes) {
        return CommandUtils.bytesToHex(derBytes);
    }

    // ===== PRIVATE DER ENCODING HELPERS =====

    /** AlgorithmIdentifier for sha256WithRSAEncryption with NULL parameters */
    private static byte[] sha256WithRsaAlgId() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(derOid(OID_SHA256_WITH_RSA));
        bos.write(new byte[]{0x05, 0x00}); // NULL
        return derSequence(bos.toByteArray());
    }

    /**
     * RelativeDistinguishedName: SET { SEQUENCE { OID, value } }
     */
    private static byte[] rdn(byte[] oid, byte[] value) throws IOException {
        ByteArrayOutputStream atv = new ByteArrayOutputStream();
        atv.write(derOid(oid));
        atv.write(value);
        ByteArrayOutputStream set = new ByteArrayOutputStream();
        set.write(derSequence(atv.toByteArray()));
        return der(0x31, set.toByteArray());
    }

    private static byte[] derSequence(byte[] content) { return der(0x30, content); }

    private static byte[] derInteger(byte[] value) { return der(0x02, value); }

    private static byte[] derOid(byte[] oid) { return der(0x06, oid); }

    /** BIT STRING: 1-byte unused-bits prefix (0x00) followed by the data */
    private static byte[] derBitString(byte[] data) {
        byte[] content = new byte[data.length + 1];
        content[0] = 0x00; // 0 unused bits
        System.arraycopy(data, 0, content, 1, data.length);
        return der(0x03, content);
    }

    /** UTF8String (tag 0x0C) */
    private static byte[] utf8(String s) {
        return der(0x0C, s.getBytes(StandardCharsets.UTF_8));
    }

    /** PrintableString (tag 0x13) — required for Country per RFC 5280 */
    private static byte[] printable(String s) {
        return der(0x13, s.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Core DER TLV encoder.
     * Handles short form (< 128 bytes), 1-byte long form (< 256 bytes), and
     * 2-byte long form (< 65536 bytes) — sufficient for all RSA key sizes.
     */
    private static byte[] der(int tag, byte[] content) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(content.length + 4);
        bos.write(tag);
        int len = content.length;
        if (len < 0x80) {
            bos.write(len);
        } else if (len < 0x100) {
            bos.write(0x81);
            bos.write(len);
        } else {
            bos.write(0x82);
            bos.write((len >> 8) & 0xFF);
            bos.write(len & 0xFF);
        }
        bos.write(content, 0, len);
        return bos.toByteArray();
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }
}
