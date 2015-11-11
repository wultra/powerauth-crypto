package io.getlime.security.powerauth.client.signature;

import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.SignatureUtils;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

public class PowerAuthClientSignature {
    
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final SignatureUtils signatureUtils = new SignatureUtils();
    
    /**
     * Generate a master secret key KEY_MASTER_SECRET using the device
     * private key KEY_DEVICE_PRIVATE and server public key KEY_SERVER_PUBLIC.
     * @param devicePrivateKey Device private key KEY_DEVICE_PRIVATE.
     * @param serverPublicKey Server public key KEY_SERVER_PUBLIC.
     * @return Computed symmetric key KEY_MASTER_SECRET.
     * @throws InvalidKeyException In case some provided key is invalid.
     */
    public SecretKey generateClientMasterSecretKey(
            PrivateKey devicePrivateKey, 
            PublicKey serverPublicKey) throws InvalidKeyException {
        return keyGenerator.computeSharedKey(devicePrivateKey, serverPublicKey);
    }
    
    /**
     * Generate a signature key KEY_SIGNATURE from master secret key
     * KEY_MASTER_SECRET using KDF.
     * @see KeyGenerator#deriveSecretKey(javax.crypto.SecretKey, java.lang.long) 
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE.
     */
    public SecretKey generateClientSignatureKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(
        		masterSecretKey,
        		PowerAuthConstants.KEY_DERIVED_KEY_SIGNATURE
        );
    }
    
    /**
     * Generate a transport key KEY_TRANSPORT from master secret key
     * KEY_MASTER_SECRET using KDF.
     * @see KeyGenerator#deriveSecretKey(javax.crypto.SecretKey, java.lang.long) 
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_TRANSPORT.
     */
    public SecretKey generateServerTransportKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(
        		masterSecretKey,
        		PowerAuthConstants.KEY_DERIVED_KEY_TRANSPORT
        );
    }
    
    /**
     * Compute a PowerAuth 2.0 signature for given data, signature key
     * and counter. Signature key KEY_SIGNATURE is a symmetric key deduced using
     * private device key KEY_DEVICE_PRIVATE and server public key
     * KEY_SERVER_PUBLIC, and then using KDF function with index 1.
     * @param data Data to be signed.
     * @param signatureKey A signature key KEY_SIGNATURE.
     * @param ctr Counter / index of the derived key KEY_DERIVED.
     * @return PowerAuth 2.0 signature for given data.
     * @throws InvalidKeyException In case signature key is invalid.
     */
    public String signatureForData(
            byte[] data,
            SecretKey signatureKey,
            long ctr) throws InvalidKeyException {
        return signatureUtils.computePowerAuthSignature(data, signatureKey, ctr);
    }
    
}
