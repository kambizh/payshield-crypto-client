package my.com.kambiz.hsm.crypto;

import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.VerificationResult;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

/**
 * Pure-JVM RSA signature verification — no HSM connection required.
 *
 * Supported hash IDs: 01 (SHA-1), 05 (SHA-224), 06 (SHA-256), 07 (SHA-384), 08 (SHA-512).
 * Supported pad modes: 01 (PKCS#1 v1.5), 04 (PSS with salt length = digest length).
 * Key type: RSA only. EC and other key types are not supported.
 */
public final class SoftwareSignatureVerifier {

    private SoftwareSignatureVerifier() {}

    private record HashSpec(String jcaName, int saltLen) {}

    private static final Map<String, HashSpec> HASH_SPECS = Map.of(
            "01", new HashSpec("SHA-1",   20),
            "05", new HashSpec("SHA-224", 28),
            "06", new HashSpec("SHA-256", 32),
            "07", new HashSpec("SHA-384", 48),
            "08", new HashSpec("SHA-512", 64)
    );

    /**
     * Verify {@code signature} over {@code messageData} using an RSA public key.
     *
     * A structurally malformed signature (bad DER encoding, wrong length) returns a
     * {@code VerificationResult} with {@code valid=false} and error code "02", matching
     * the behaviour of a valid-but-mismatched signature — it never throws for bad signature
     * bytes. Only configuration errors (unsupported hashId/padMode, non-RSA key DER) throw.
     *
     * @param signature    raw signature bytes
     * @param messageData  original signed message
     * @param publicKeyDer DER-encoded SubjectPublicKeyInfo (X.509) — RSA keys only
     * @param hashId       payShield hash algorithm ID: 01/05/06/07/08
     * @param padMode      payShield padding mode ID: 01 (PKCS#1 v1.5) or 04 (PSS)
     * @return VerificationResult — never returns {@code null}
     * @throws IllegalArgumentException if hashId or padMode are unsupported, or the key is not RSA
     * @throws PayShieldException if the JCA provider cannot be initialised (provider misconfiguration)
     */
    public static VerificationResult verify(byte[] signature, byte[] messageData,
                                             byte[] publicKeyDer,
                                             String hashId, String padMode) {
        HashSpec spec = HASH_SPECS.get(hashId);
        if (spec == null) {
            throw new IllegalArgumentException(
                    "Unsupported hash ID for software verification: " + hashId
                    + ". Supported values: 01 (SHA-1), 05 (SHA-224), 06 (SHA-256),"
                    + " 07 (SHA-384), 08 (SHA-512).");
        }

        try {
            PublicKey publicKey;
            try {
                // Try X.509 SubjectPublicKeyInfo format first (standard)
                publicKey = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(publicKeyDer));
            } catch (InvalidKeySpecException e) {
                // payShield EI command returns PKCS#1 RSAPublicKey (inner structure only,
                // starts with SEQUENCE { INTEGER modulus, INTEGER exponent }) without the
                // X.509 SubjectPublicKeyInfo AlgorithmIdentifier wrapper.
                // Wrap it transparently so the JVM can accept it.
                try {
                    publicKey = KeyFactory.getInstance("RSA")
                            .generatePublic(new X509EncodedKeySpec(pkcs1ToSubjectPublicKeyInfo(publicKeyDer)));
                } catch (Exception e2) {
                    throw new IllegalArgumentException(
                            "publicKeyDer is not a valid RSA public key in either X.509 SubjectPublicKeyInfo "
                            + "or PKCS#1 RSAPublicKey format. "
                            + "EC and other key types are not supported by software verification.", e);
                }
            }

            Signature verifier;
            if ("04".equals(padMode)) {
                verifier = Signature.getInstance("RSASSA-PSS");
                verifier.setParameter(new PSSParameterSpec(
                        spec.jcaName(), "MGF1", new MGF1ParameterSpec(spec.jcaName()), spec.saltLen(), 1));
            } else if ("01".equals(padMode)) {
                verifier = Signature.getInstance(spec.jcaName().replace("-", "") + "withRSA");
            } else {
                throw new IllegalArgumentException(
                        "Unsupported pad mode for software verification: " + padMode
                        + ". Supported values: 01 (PKCS#1 v1.5), 04 (PSS).");
            }

            verifier.initVerify(publicKey);
            verifier.update(messageData);

            boolean valid;
            try {
                valid = verifier.verify(signature);
            } catch (SignatureException e) {
                // Structurally malformed signature bytes — treat as verification failure,
                // not an infrastructure error, so callers get a consistent VerificationResult.
                return new VerificationResult(false, "02",
                        "invalid signature encoding: " + e.getMessage(), null);
            }

            return new VerificationResult(
                    valid,
                    valid ? "00" : "02",
                    valid ? "No error" : "Verification failure (signature mismatch)",
                    null);

        } catch (IllegalArgumentException e) {
            throw e;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new PayShieldException(
                    "JCA provider error during software verification: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new PayShieldException(
                    "Software signature verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Wraps a PKCS#1 RSAPublicKey DER structure in an X.509 SubjectPublicKeyInfo envelope
     * so the JVM's KeyFactory can accept it.
     *
     * payShield's EI command returns the public key as a bare PKCS#1 RSAPublicKey
     * (SEQUENCE { INTEGER modulus, INTEGER exponent }) without the SubjectPublicKeyInfo
     * wrapper (AlgorithmIdentifier + BIT STRING). This method adds that wrapper.
     *
     * Result structure:
     *   SEQUENCE {
     *     SEQUENCE { OID rsaEncryption, NULL }   -- AlgorithmIdentifier
     *     BIT STRING { 0x00, <pkcs1Key bytes> }  -- public key bits
     *   }
     */
    private static byte[] pkcs1ToSubjectPublicKeyInfo(byte[] pkcs1Key) {
        // Fixed RSA AlgorithmIdentifier: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
        byte[] algId = {
            0x30, 0x0D,
            0x06, 0x09, 0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x01,
            0x05, 0x00
        };

        // BIT STRING content = unused-bits byte (0x00) + PKCS#1 key bytes
        int bitStringContentLen = 1 + pkcs1Key.length;
        byte[] bitStringLenBytes = encodeDerLength(bitStringContentLen);

        // Outer SEQUENCE content = algId + BIT STRING tag + BIT STRING length + BIT STRING value
        int outerContentLen = algId.length + 1 + bitStringLenBytes.length + bitStringContentLen;
        byte[] outerLenBytes = encodeDerLength(outerContentLen);

        ByteArrayOutputStream out = new ByteArrayOutputStream(1 + outerLenBytes.length + outerContentLen);
        try {
            out.write(0x30);              // SEQUENCE tag
            out.write(outerLenBytes);
            out.write(algId);
            out.write(0x03);              // BIT STRING tag
            out.write(bitStringLenBytes);
            out.write(0x00);              // no unused bits
            out.write(pkcs1Key);
        } catch (Exception e) {
            throw new IllegalStateException("Unreachable: ByteArrayOutputStream never throws", e);
        }
        return out.toByteArray();
    }

    /** Encode a DER length field (1-byte short form or 2/3-byte long form). */
    private static byte[] encodeDerLength(int len) {
        if (len < 0x80)   return new byte[] { (byte) len };
        if (len < 0x100)  return new byte[] { (byte) 0x81, (byte) len };
        return new byte[] { (byte) 0x82, (byte)(len >> 8), (byte)(len & 0xFF) };
    }
}
