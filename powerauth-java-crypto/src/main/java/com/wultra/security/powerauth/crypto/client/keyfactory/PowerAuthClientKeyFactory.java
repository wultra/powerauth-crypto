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
package com.wultra.security.powerauth.crypto.client.keyfactory;

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthDerivedKey;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Class implementing client side key factory for keys related to PowerAuth processes (V3).
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthClientKeyFactory {

    private final KeyGenerator keyGenerator = new KeyGenerator();

    /**
     * Return a correct list of keys for given factor key.
     * @param powerAuthCodeType Requested type of a factor.
     * @param possessionFactorKey Possession factor related factor key.
     * @param knowledgeFactorKey Knowledge factor related factor key.
     * @param biometryFactorKey Biometry factor related factor key.
     * @return List with correct keys
     */
    public List<SecretKey> keysForAuthenticationCodeType(PowerAuthCodeType powerAuthCodeType, SecretKey possessionFactorKey, SecretKey knowledgeFactorKey, SecretKey biometryFactorKey) {

        List<SecretKey> factorKeys = new ArrayList<>();

        if (powerAuthCodeType == null) {
            return factorKeys;
        }

        if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION)) {

            factorKeys.add(possessionFactorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.KNOWLEDGE)) {

            factorKeys.add(knowledgeFactorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.BIOMETRY)) {

            factorKeys.add(biometryFactorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_KNOWLEDGE)) {

            factorKeys.add(possessionFactorKey);
            factorKeys.add(knowledgeFactorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_BIOMETRY)) {

            factorKeys.add(possessionFactorKey);
            factorKeys.add(biometryFactorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY)) {

            factorKeys.add(possessionFactorKey);
            factorKeys.add(knowledgeFactorKey);
            factorKeys.add(biometryFactorKey);

        }

        return factorKeys;

    }

    /**
     * Generate a list with authentication code keys for given authentication code type and master
     * secret
     * @param powerAuthCodeType Requested authentication code type
     * @param masterSecretKey Master Key Secret
     * @return List with keys constructed from master secret that are needed to
     *         get requested authentication code type.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public List<SecretKey> keysForAuthenticationCodeType(PowerAuthCodeType powerAuthCodeType, SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {

        List<SecretKey> factorKeys = new ArrayList<>();

        if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION)) {

            SecretKey factorKey = generateClientPossessionFactorKey(masterSecretKey);
            factorKeys.add(factorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.KNOWLEDGE)) {

            SecretKey factorKey = generateClientKnowledgeFactorKey(masterSecretKey);
            factorKeys.add(factorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.BIOMETRY)) {

            SecretKey factorKey = generateClientBiometryFactorKey(masterSecretKey);
            factorKeys.add(factorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_KNOWLEDGE)) {

            SecretKey factorKey = generateClientPossessionFactorKey(masterSecretKey);
            factorKeys.add(factorKey);
            factorKey = generateClientKnowledgeFactorKey(masterSecretKey);
            factorKeys.add(factorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_BIOMETRY)) {

            SecretKey factorKey = generateClientPossessionFactorKey(masterSecretKey);
            factorKeys.add(factorKey);
            factorKey = generateClientBiometryFactorKey(masterSecretKey);
            factorKeys.add(factorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY)) {

            SecretKey factorKey = generateClientPossessionFactorKey(masterSecretKey);
            factorKeys.add(factorKey);
            factorKey = generateClientKnowledgeFactorKey(masterSecretKey);
            factorKeys.add(factorKey);
            factorKey = generateClientBiometryFactorKey(masterSecretKey);
            factorKeys.add(factorKey);

        }

        return factorKeys;

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
     * Generate a factor key KEY_FACTOR_BIOMETRY from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey
     *            Master secret key KEY_MASTER_SECRET.
     * @return An instance of factor key KEY_FACTOR_BIOMETRY.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateClientBiometryFactorKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(masterSecretKey, PowerAuthDerivedKey.FACTOR_BIOMETRY.getIndex());
    }

    /**
     * Generate a factor key KEY_FACTOR_KNOWLEDGE from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey
     *            Master secret key KEY_MASTER_SECRET.
     * @return An instance of factor key KEY_FACTOR_KNOWLEDGE.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateClientKnowledgeFactorKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(masterSecretKey, PowerAuthDerivedKey.FACTOR_KNOWLEDGE.getIndex());
    }

    /**
     * Generate a factor key KEY_FACTOR_POSSESSION from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey
     *            Master secret key KEY_MASTER_SECRET.
     * @return An instance of factor key KEY_FACTOR_POSSESSION.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateClientPossessionFactorKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(masterSecretKey, PowerAuthDerivedKey.FACTOR_POSSESSION.getIndex());
    }

    /**
     * Generate a transport key KEY_ENCRYPTED_VAULT from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey
     *            Master secret key KEY_MASTER_SECRET.
     * @return An instance of vault key KEY_ENCRYPTED_VAULT.
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
     * @return An instance of key KEY_TRANSPORT.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerTransportKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(masterSecretKey, PowerAuthDerivedKey.TRANSPORT.getIndex());
    }

}
