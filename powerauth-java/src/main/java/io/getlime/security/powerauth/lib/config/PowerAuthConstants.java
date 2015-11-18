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
    public static final int SIGNATURE_LENGTH = 8;

    /**
     * How many failed signatures cause activation record blocking
     */
    public static final long SIGNATURE_MAX_FAILED_ATTEMPTS = 5L;

    /**
     * When validating the signature, how many iterations ahead too look
     */
    public static final long SIGNATURE_VALIDATION_LOOKAHEAD = 20L;

    public class KEY_DERIVED {
    	
    	/**
         * Index of the signature key KEY_SIGNATURE_POSSESSION.
         */
        public static final int SIGNATURE_POSSESSION = 1;
        
        /**
         * Index of the signature key KEY_SIGNATURE_KNOWLEDGE.
         */
        public static final int SIGNATURE_KNOWLEDGE = 2;
        
        /**
         * Index of the signature key KEY_SIGNATURE_BIOMETRY.
         */
        public static final int SIGNATURE_BIOMETRY = 3;

        /**
         * Index of the signature key KEY_TRANSPORT.
         */
        public static final int TRANSPORT = 1000;
        
        /**
         * Index of the signature key KEY_ENCRYPTED_VAULT.
         */
        public static final int ENCRYPTED_VAULT = 2000;
        
    }
    
    public class SIGNATURE_TYPES {
    	
    	/**
    	 * Signature uses a single signature key for 1FA using the "possession" factor.
    	 */
    	public static final String POSSESSION = "possession";
    	
    	/**
    	 * Signature uses a single signature key for 1FA using the "knowledge" factor.
    	 */
    	public static final String KNOWLEDGE = "knowledge";
    	
    	/**
    	 * Signature uses a single signature key for 1FA using the "biometry" factor.
    	 */
    	public static final String BIOMETRY = "biometry";
    	
    	/**
    	 * Signature uses two signature keys for 2FA using the "possession" and "knowledge" factor.
    	 */
    	public static final String POSSESSION_KNOWLEDGE = "possession_knowledge";
    	
    	/**
    	 * Signature uses two signature keys for 2FA using the "possession" and "biometry" factor.
    	 */
    	public static final String POSSESSION_BIOMETRY = "possession_biometry";
    	
    	/**
    	 * Signature uses three signature keys for 3FA using the "possession", "knowledge" and "biometry" factor.
    	 */
    	public static final String POSSESSION_KNOWLEDGE_BIOMETRY = "possession_knowledge_biometry";
    	
    }

}
