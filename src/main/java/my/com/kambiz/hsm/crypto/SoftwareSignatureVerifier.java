package my.com.kambiz.hsm.crypto;

import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.VerificationResult;

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
                publicKey = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(publicKeyDer));
            } catch (InvalidKeySpecException e) {
                throw new IllegalArgumentException(
                        "publicKeyDer is not a valid RSA SubjectPublicKeyInfo (X.509) key. "
                        + "EC and other key types are not supported by software verification.", e);
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
}
