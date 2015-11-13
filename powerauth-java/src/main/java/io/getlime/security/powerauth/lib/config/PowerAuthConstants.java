package io.getlime.security.powerauth.lib.config;

public class PowerAuthConstants {

    /**
     * How many iterations should be used for PBKDF2 key derivation.
     */
    public static final int PBKDF_ITERATIONS = 10000;

    /**
     * When a duplicate activation ID is encountered during the activation, how
     * many times generate a new one.
     */
    public static final int ACTIVATION_GENERATE_ACTIVATION_ID_ITERATIONS = 10;

    /**
     * When a duplicate activation short ID is encountered during the
     * activation, how many times generate a new one.
     */
    public static final int ACTIVATION_GENERATE_ACTIVATION_SHORT_ID_ITERATIONS = 10;

    /**
     * How many seconds should be CREATED or OTP_USED record usable for
     * completing the activation.
     */
    public static final int ACTIVATION_VALIDITY_BEFORE_ACTIVE = 2 * 60;

    /**
     * Length of device public key fingerprint.
     */
    public static final int FINGERPRINT_LENGTH = 8;

    /**
     * Signature length (number of decimal numbers representing signature)
     */
    public static final int SIGNATURE_LENGTH = 10;

    /**
     * How many failed signatures cause activation record blocking
     */
    public static final long SIGNATURE_MAX_FAILED_ATTEMPTS = 5L;

    /**
     * When validating the signature, how many iterations ahead too look
     */
    public static final long SIGNATURE_VALIDATION_LOOKAHEAD = 20L;

    /**
     * Index of the signature key KEY_SIGNATURE.
     */
    public static final int KEY_DERIVED_KEY_SIGNATURE = 1;

    /**
     * Index of the signature key KEY_TRANSPORT.
     */
    public static final int KEY_DERIVED_KEY_TRANSPORT = 2;

}
