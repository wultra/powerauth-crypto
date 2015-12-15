/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.getlime.security.powerauth.client.signature;

import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.SignatureUtils;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import javax.crypto.SecretKey;

public class PowerAuthClientSignature {

    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final SignatureUtils signatureUtils = new SignatureUtils();

    /**
     * Generate a master secret key KEY_MASTER_SECRET using the device private
     * key KEY_DEVICE_PRIVATE and server public key KEY_SERVER_PUBLIC.
     *
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
     * Generate a signature key KEY_SIGNATURE_POSSESSION from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(javax.crypto.SecretKey, java.lang.long)
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE_POSSESSION.
     */
    public SecretKey generateClientSignaturePossessionKey(SecretKey masterSecretKey) {
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
    public SecretKey generateClientSignatureKnowledgeKey(SecretKey masterSecretKey) {
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
    public SecretKey generateClientSignatureBiometryKey(SecretKey masterSecretKey) {
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
    public SecretKey generateServerEncryptedVaultKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthConstants.KEY_DERIVED.ENCRYPTED_VAULT
        );
    }

    /**
     * Compute a PowerAuth 2.0 signature for given data, signature keys and
     * counter. Signature keys are symmetric keys deduced using
     * private device key KEY_DEVICE_PRIVATE and server public key
     * KEY_SERVER_PUBLIC, and then using KDF function with proper index. See
     * PowerAuth protocol specification for details.
     *
     * @param data Data to be signed.
     * @param signatureKeys A signature keys.
     * @param ctr Counter / index of the derived key KEY_DERIVED.
     * @return PowerAuth 2.0 signature for given data.
     * @throws InvalidKeyException In case signature key is invalid.
     */
    public String signatureForData(
            byte[] data,
            List<SecretKey> signatureKeys,
            long ctr) throws InvalidKeyException {
        return signatureUtils.computePowerAuthSignature(data, signatureKeys, ctr);
    }

}
