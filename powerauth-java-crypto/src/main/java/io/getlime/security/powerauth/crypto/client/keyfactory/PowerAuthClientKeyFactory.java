/*
 * PowerAuth Crypto Library
 * Copyright 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.client.keyfactory;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthDerivedKey;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Class implementing client side key factory for keys related to PowerAuth processes.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PowerAuthClientKeyFactory {

    private final KeyGenerator keyGenerator = new KeyGenerator();

    /**
     * Return a correct list of keys for given signature type.
     * @param signatureType Requested type of a signature.
     * @param possessionSignatureKey Possession factor related signature key.
     * @param knowledgeSignatureKey Knowledge factor related signature key.
     * @param biometrySignatureKey Biometry factor related signature key.
     * @return List with correct keys
     */
    public List<SecretKey> keysForSignatureType(PowerAuthSignatureTypes signatureType, SecretKey possessionSignatureKey, SecretKey knowledgeSignatureKey, SecretKey biometrySignatureKey) {

        List<SecretKey> signatureKeys = new ArrayList<>();

        if (signatureType == null) {
            return signatureKeys;
        }

        if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION)) {

            signatureKeys.add(possessionSignatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.KNOWLEDGE)) {

            signatureKeys.add(knowledgeSignatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.BIOMETRY)) {

            signatureKeys.add(biometrySignatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE)) {

            signatureKeys.add(possessionSignatureKey);
            signatureKeys.add(knowledgeSignatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION_BIOMETRY)) {

            signatureKeys.add(possessionSignatureKey);
            signatureKeys.add(biometrySignatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY)) {

            signatureKeys.add(possessionSignatureKey);
            signatureKeys.add(knowledgeSignatureKey);
            signatureKeys.add(biometrySignatureKey);

        }

        return signatureKeys;

    }

    /**
     * Generate a list with signature keys for given signature type and master
     * secret
     * @param signatureType Requested signature type
     * @param masterSecretKey Master Key Secret
     * @return List with keys constructed from master secret that are needed to
     *         get requested signature type.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public List<SecretKey> keysForSignatureType(PowerAuthSignatureTypes signatureType, SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {

        List<SecretKey> signatureKeys = new ArrayList<>();

        if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION)) {

            SecretKey signatureKey = generateClientSignaturePossessionKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.KNOWLEDGE)) {

            SecretKey signatureKey = generateClientSignatureKnowledgeKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.BIOMETRY)) {

            SecretKey signatureKey = generateClientSignatureBiometryKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE)) {

            SecretKey signatureKey = generateClientSignaturePossessionKey(masterSecretKey);
            signatureKeys.add(signatureKey);
            signatureKey = generateClientSignatureKnowledgeKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION_BIOMETRY)) {

            SecretKey signatureKey = generateClientSignaturePossessionKey(masterSecretKey);
            signatureKeys.add(signatureKey);
            signatureKey = generateClientSignatureBiometryKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY)) {

            SecretKey signatureKey = generateClientSignaturePossessionKey(masterSecretKey);
            signatureKeys.add(signatureKey);
            signatureKey = generateClientSignatureKnowledgeKey(masterSecretKey);
            signatureKeys.add(signatureKey);
            signatureKey = generateClientSignatureBiometryKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        }

        return signatureKeys;

    }

    /**
     * Generate a master secret key KEY_MASTER_SECRET using the device private
     * key KEY_DEVICE_PRIVATE and server public key KEY_SERVER_PUBLIC.
     *
     * @param devicePrivateKey
     *            Device private key KEY_DEVICE_PRIVATE.
     * @param serverPublicKey
     *            Server public key KEY_SERVER_PUBLIC.
     * @return Computed symmetric key KEY_MASTER_SECRET.
     * @throws InvalidKeyException
     *             In case some provided key is invalid.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateClientMasterSecretKey(PrivateKey devicePrivateKey, PublicKey serverPublicKey) throws InvalidKeyException, CryptoProviderException {
        return keyGenerator.computeSharedKey(devicePrivateKey, serverPublicKey);
    }

    /**
     * Generate a signature key KEY_SIGNATURE_BIOMETRY from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey
     *            Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE_BIOMETRY.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateClientSignatureBiometryKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(masterSecretKey, PowerAuthDerivedKey.SIGNATURE_BIOMETRY.getIndex());
    }

    /**
     * Generate a signature key KEY_SIGNATURE_KNOWLEDGE from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey
     *            Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE_KNOWLEDGE.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateClientSignatureKnowledgeKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(masterSecretKey, PowerAuthDerivedKey.SIGNATURE_KNOWLEDGE.getIndex());
    }

    /**
     * Generate a signature key KEY_SIGNATURE_POSSESSION from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey
     *            Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE_POSSESSION.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateClientSignaturePossessionKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(masterSecretKey, PowerAuthDerivedKey.SIGNATURE_POSSESSION.getIndex());
    }

    /**
     * Generate a transport key KEY_ENCRYPTED_VAULT from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey
     *            Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_ENCRYPTED_VAULT.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerEncryptedVaultKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(masterSecretKey, PowerAuthDerivedKey.ENCRYPTED_VAULT.getIndex());
    }

    /**
     * Generate a transport key KEY_TRANSPORT from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey
     *            Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_TRANSPORT.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerTransportKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(masterSecretKey, PowerAuthDerivedKey.TRANSPORT.getIndex());
    }

}
