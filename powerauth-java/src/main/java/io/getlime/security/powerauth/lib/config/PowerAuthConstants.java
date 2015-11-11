package io.getlime.security.powerauth.lib.config;

public class PowerAuthConstants {

	/**
     * How many iterations should be used for PBKDF2 key derivation.
     */
    public static final int PBKDF_ITERATIONS = 10000;
    
    /**
     * Length of device public key fingerprint.
     */
    public static final int FINGERPRINT_LENGTH = 8;
    
    /**
     * Signature length (number of decimal numbers representing signature)
     */
    public static final int SIGNATURE_LENGTH = 8;
    
    /**
     * How many failed signatures cause activation record blocking
     */
    public static final long SIGNATURE_MAX_FAILED_ATTEMPTS = 5L;
    
    /**
     * Index of the signature key KEY_SIGNATURE.
     */
    public static final int KEY_DERIVED_KEY_SIGNATURE = 1;
    
    /**
     * Index of the signature key KEY_TRANSPORT.
     */
    public static final int KEY_DERIVED_KEY_TRANSPORT = 2;
    
}
