/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.crypto.server.keyfactory;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthDerivedKey;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;


/**
 * Key factory used on server side to generate PowerAuth related keys.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
public class PowerAuthServerKeyFactory {

    private final KeyGenerator keyGenerator = new KeyGenerator();

    /**
     * Generate a list with signature keys for given signature type and master secret
     * @param signatureType Requested signature type
     * @param masterSecretKey Master Key Secret
     * @return List with keys constructed from master secret that are needed to get
     * requested signature type.
     */
    public List<SecretKey> keysForSignatureType(PowerAuthSignatureTypes signatureType, SecretKey masterSecretKey) {

        List<SecretKey> signatureKeys = new ArrayList<>();

        if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION)) {

            SecretKey signatureKey = generateServerSignaturePossessionKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.KNOWLEDGE)) {

            SecretKey signatureKey = generateServerSignatureKnowledgeKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.BIOMETRY)) {

            SecretKey signatureKey = generateServerSignatureBiometryKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE)) {

            SecretKey signatureKey = generateServerSignaturePossessionKey(masterSecretKey);
            signatureKeys.add(signatureKey);
            signatureKey = generateServerSignatureKnowledgeKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION_BIOMETRY)) {

            SecretKey signatureKey = generateServerSignaturePossessionKey(masterSecretKey);
            signatureKeys.add(signatureKey);
            signatureKey = generateServerSignatureBiometryKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY)) {

            SecretKey signatureKey = generateServerSignaturePossessionKey(masterSecretKey);
            signatureKeys.add(signatureKey);
            signatureKey = generateServerSignatureKnowledgeKey(masterSecretKey);
            signatureKeys.add(signatureKey);
            signatureKey = generateServerSignatureBiometryKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        }

        return signatureKeys;

    }

    /**
     * Generate a transport key KEY_ENCRYPTED_VAULT from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, long)
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_ENCRYPTED_VAULT.
     */
    public SecretKey generateServerEncryptedVaultKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.ENCRYPTED_VAULT.getIndex()
        );
    }

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
     * Generate a signature key KEY_SIGNATURE_BIOMETRY from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, long)
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE_BIOMETRY.
     */
    public SecretKey generateServerSignatureBiometryKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.SIGNATURE_BIOMETRY.getIndex()
        );
    }

    /**
     * Generate a signature key KEY_SIGNATURE_KNOWLEDGE from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, long)
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE_KNOWLEDGE.
     */
    public SecretKey generateServerSignatureKnowledgeKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.SIGNATURE_KNOWLEDGE.getIndex()
        );
    }

    /**
     * Generate a signature key KEY_SIGNATURE_POSSESSION from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, long)
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE_POSSESSION.
     */
    public SecretKey generateServerSignaturePossessionKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.SIGNATURE_POSSESSION.getIndex()
        );
    }

    /**
     * Generate a transport key KEY_TRANSPORT from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, long)
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_TRANSPORT.
     */
    public SecretKey generateServerTransportKey(SecretKey masterSecretKey) {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.TRANSPORT.getIndex()
        );
    }

}
