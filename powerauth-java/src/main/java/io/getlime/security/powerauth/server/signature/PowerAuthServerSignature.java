package io.getlime.security.powerauth.server.signature;

import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.SignatureUtils;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

public class PowerAuthServerSignature {
    
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final SignatureUtils signatureUtils = new SignatureUtils();
    
    /**
     * Generate a master secret key KEY_MASTER_SECRET using the server
     * private key KEY_SERVER_PRIVATE and device public key KEY_DEVICE_PUBLIC.
     * @param serverPrivateKey Server private key KEY_SERVER_PRIVATE.
     * @param devicePublicKey Device public key KEY_DEVICE_PUBLIC.
     * @return Computed symmetric key KEY_MASTER_SECRET.
     * @throws InvalidKeyException In case some provided key is invalid.
     */
    public SecretKey generateServerMasterSecretKey(
            PrivateKey serverPrivateKey, 
            PublicKey devicePublicKey) throws InvalidKeyException {
        return keyGenerator.computeSharedKey(serverPrivateKey, devicePublicKey);
    }
    
    /**
     * Generate a signature key KEY_SIGNATURE from master secret key
     * KEY_MASTER_SECRET using KDF.
     * @see KeyGenerator#deriveSecretKey(javax.crypto.SecretKey, java.lang.Long) 
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE.
     */
    public SecretKey generateServerSignatureKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(masterSecretKey,
        		new Long(PowerAuthConstants.KEY_DERIVED_KEY_SIGNATURE)
        );
    }
    
    /**
     * Generate a transport key KEY_TRANSPORT from master secret key
     * KEY_MASTER_SECRET using KDF.
     * @see KeyGenerator#deriveSecretKey(javax.crypto.SecretKey, java.lang.Long) 
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_TRANSPORT.
     */
    public SecretKey generateServerTransportKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(masterSecretKey,
        		new Long(PowerAuthConstants.KEY_DERIVED_KEY_TRANSPORT)
        );
    }
    
    /**
     * Verify a PowerAuth 2.0 signature against data using signature key
     * and counter.
     * @param data Signed data.
     * @param signature Signature for the data.
     * @param signatureKey Key used for signature.
     * @param ctr Counter / derived signing key index.
     * @return Returns "true" if the signature matches, "false" otherwise.
     * @throws InvalidKeyException 
     */
    public boolean verifySignatureForData(
            byte[] data,
            String signature,
            SecretKey signatureKey,
            Long ctr) throws InvalidKeyException {
        return signatureUtils.validatePowerAuthSignature(data, signature, signatureKey, ctr);
    }
    
}
