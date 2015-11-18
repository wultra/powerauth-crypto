package io.getlime.security.powerauth.server.signature;

import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.SignatureUtils;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import javax.crypto.SecretKey;

public class PowerAuthServerSignature {

    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final SignatureUtils signatureUtils = new SignatureUtils();

    /**
     * Generate a master secret key KEY_MASTER_SECRET using the server private
     * key KEY_SERVER_PRIVATE and device public key KEY_DEVICE_PUBLIC.
     *
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
     * Generate a signature key KEY_SIGNATURE_POSSESSION from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(javax.crypto.SecretKey, java.lang.long)
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE_POSSESSION.
     */
    public SecretKey generateServerSignaturePossessionKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthConstants.KEY_DERIVED.SIGNATURE_POSSESSION
        );
    }
    
    /**
     * Generate a signature key KEY_SIGNATURE_KNOWLEDGE from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(javax.crypto.SecretKey, java.lang.long)
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE_KNOWLEDGE.
     */
    public SecretKey generateServerSignatureKnowledgeKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthConstants.KEY_DERIVED.SIGNATURE_KNOWLEDGE
        );
    }
    
    /**
     * Generate a signature key KEY_SIGNATURE_BIOMETRY from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(javax.crypto.SecretKey, java.lang.long)
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE_BIOMETRY.
     */
    public SecretKey generateServerSignatureBiometryKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthConstants.KEY_DERIVED.SIGNATURE_BIOMETRY
        );
    }

    /**
     * Generate a transport key KEY_TRANSPORT from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(javax.crypto.SecretKey, java.lang.long)
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_TRANSPORT.
     */
    public SecretKey generateServerTransportKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthConstants.KEY_DERIVED.TRANSPORT
        );
    }
    
    /**
     * Generate a transport key KEY_ENCRYPTED_VAULT from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(javax.crypto.SecretKey, java.lang.long)
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_ENCRYPTED_VAULT.
     */
    public SecretKey generateServerEndryptedVaultKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthConstants.KEY_DERIVED.ENCRYPTED_VAULT
        );
    }

    /**
     * Verify a PowerAuth 2.0 signature against data using signature key list and
     * counter.
     *
     * @param data Signed data.
     * @param signature Signature for the data.
     * @param signatureKeys Keys used for signature.
     * @param ctr Counter / derived signing key index.
     * @return Returns "true" if the signature matches, "false" otherwise.
     * @throws InvalidKeyException
     */
    public boolean verifySignatureForData(
            byte[] data,
            String signature,
            List<SecretKey> signatureKeys,
            long ctr) throws InvalidKeyException {
        return signatureUtils.validatePowerAuthSignature(data, signature, signatureKeys, ctr);
    }

}
