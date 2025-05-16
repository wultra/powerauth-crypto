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
package com.wultra.security.powerauth.crypto.server.keyfactory;

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
 * Key factory used on server side to generate PowerAuth related keys.
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
 *
 */
public class PowerAuthServerKeyFactory {

    private final KeyGenerator keyGenerator = new KeyGenerator();

    /**
     * Generate a list with authentication code keys for given authentication code type and master secret
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param powerAuthCodeType Requested authentication code type
     * @param masterSecretKey Master Key Secret
     * @return List with keys constructed from master secret that are needed to get
     * requested authentication code type.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public List<SecretKey> keysForAuthenticationCodeType(PowerAuthCodeType powerAuthCodeType, SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {

        List<SecretKey> factorKeys = new ArrayList<>();

        if (powerAuthCodeType == null) {
            return factorKeys;
        }

        if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION)) {

            SecretKey factorKey = generateServerPossessionFactorKey(masterSecretKey);
            factorKeys.add(factorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.KNOWLEDGE)) {

            SecretKey factorKey = generateServerKnowledgeFactorKey(masterSecretKey);
            factorKeys.add(factorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.BIOMETRY)) {

            SecretKey factorKey = generateServerBiometryFactorKey(masterSecretKey);
            factorKeys.add(factorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_KNOWLEDGE)) {

            SecretKey factorKey = generateServerPossessionFactorKey(masterSecretKey);
            factorKeys.add(factorKey);
            factorKey = generateServerKnowledgeFactorKey(masterSecretKey);
            factorKeys.add(factorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_BIOMETRY)) {

            SecretKey factorKey = generateServerPossessionFactorKey(masterSecretKey);
            factorKeys.add(factorKey);
            factorKey = generateServerBiometryFactorKey(masterSecretKey);
            factorKeys.add(factorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY)) {

            SecretKey factorKey = generateServerPossessionFactorKey(masterSecretKey);
            factorKeys.add(factorKey);
            factorKey = generateServerKnowledgeFactorKey(masterSecretKey);
            factorKeys.add(factorKey);
            factorKey = generateServerBiometryFactorKey(masterSecretKey);
            factorKeys.add(factorKey);

        }

        return factorKeys;

    }

    /**
     * Generate a transport key KEY_ENCRYPTED_VAULT from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of key KEY_ENCRYPTED_VAULT.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerEncryptedVaultKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.ENCRYPTED_VAULT.getIndex()
        );
    }

    /**
     * Generate a master secret key KEY_MASTER_SECRET using the server private
     * key KEY_SERVER_PRIVATE and device public key KEY_DEVICE_PUBLIC.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param serverPrivateKey Server private key KEY_SERVER_PRIVATE.
     * @param devicePublicKey Device public key KEY_DEVICE_PUBLIC.
     * @return Computed symmetric key KEY_MASTER_SECRET.
     * @throws InvalidKeyException In case some provided key is invalid.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerMasterSecretKey(
            PrivateKey serverPrivateKey,
            PublicKey devicePublicKey) throws InvalidKeyException, CryptoProviderException {
        return keyGenerator.computeSharedKey(serverPrivateKey, devicePublicKey);
    }

    /**
     * Generate a factor key KEY_FACTOR_BIOMETRY from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of factor key KEY_FACTOR_BIOMETRY.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerBiometryFactorKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.FACTOR_BIOMETRY.getIndex()
        );
    }

    /**
     * Generate a factor key KEY_FACTOR_KNOWLEDGE from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of factor key KEY_FACTOR_KNOWLEDGE.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerKnowledgeFactorKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.FACTOR_KNOWLEDGE.getIndex()
        );
    }

    /**
     * Generate a factor key KEY_FACTOR_POSSESSION from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of factor key KEY_FACTOR_POSSESSION.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerPossessionFactorKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.FACTOR_POSSESSION.getIndex()
        );
    }

    /**
     * Generate a transport key KEY_TRANSPORT from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of factor key KEY_TRANSPORT.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerTransportKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.TRANSPORT.getIndex()
        );
    }

    /**
     * Derive transport key KEY_TRANSPORT in two steps:
     * 1. Generate KEY_MASTER_SECRET using KEY_SERVER_PRIVATE and KEY_DEVICE_PUBLIC.
     * 2. Generate KEY_TRANSPORT from previously generated KEY_MASTER_SECRET using KDF.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param serverPrivateKey Server private key KEY_SERVER_PRIVATE.
     * @param devicePublicKey Device public key KEY_DEVICE_PUBLIC.
     * @return Derived transport key KEY_TRANSPORT.
     * @throws InvalidKeyException In case key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey deriveTransportKey(PrivateKey serverPrivateKey, PublicKey devicePublicKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        // Compute master secret key using ECDH
        SecretKey masterSecretKey = generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
        // Generate server transport key from master secret key
        return generateServerTransportKey(masterSecretKey);
    }

}
