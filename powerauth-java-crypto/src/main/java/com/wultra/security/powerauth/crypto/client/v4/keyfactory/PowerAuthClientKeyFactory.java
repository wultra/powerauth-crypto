/*
 * PowerAuth Crypto Library
 * Copyright 2025 Wultra s.r.o.
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
package com.wultra.security.powerauth.crypto.client.v4.keyfactory;

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyFactory;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Class implementing client side key factory for keys related to PowerAuth processes (V4).
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthClientKeyFactory {

    /**
     * Return a correct list of keys for given factor key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param powerAuthCodeType Requested type of a factor.
     * @param possessionFactorKey Possession factor related factor key.
     * @param knowledgeFactorKey Knowledge factor related factor key.
     * @param biometryFactorKey Biometry factor related factor key.
     * @return List with correct keys
     */
    public List<SecretKey> keysForAuthenticationCodeType(PowerAuthCodeType powerAuthCodeType, SecretKey possessionFactorKey, SecretKey knowledgeFactorKey, SecretKey biometryFactorKey) {
        final List<SecretKey> factorKeys = new ArrayList<>();
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
     * Generate a list with authentication code keys for given authentication code type and activation secret key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param powerAuthCodeType Requested authentication code type.
     * @param keyActivationSecret Activation secret key KEY_ACTIVATION_SECRET.
     * @return List with keys constructed from master secret that are needed to
     *         get requested authentication code type.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public List<SecretKey> keysForAuthenticationCodeType(PowerAuthCodeType powerAuthCodeType, SecretKey keyActivationSecret) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        final List<SecretKey> factorKeys = new ArrayList<>();
        if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION)) {
            final SecretKey factorKey = generateClientPossessionFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
        } else if (powerAuthCodeType.equals(PowerAuthCodeType.KNOWLEDGE)) {
            final SecretKey factorKey = generateClientKnowledgeFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
        } else if (powerAuthCodeType.equals(PowerAuthCodeType.BIOMETRY)) {
            final SecretKey factorKey = generateClientBiometryFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_KNOWLEDGE)) {
            SecretKey factorKey = generateClientPossessionFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
            factorKey = generateClientKnowledgeFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_BIOMETRY)) {
            SecretKey factorKey = generateClientPossessionFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
            factorKey = generateClientBiometryFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY)) {
            SecretKey factorKey = generateClientPossessionFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
            factorKey = generateClientKnowledgeFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
            factorKey = generateClientBiometryFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
        }
        return factorKeys;
    }

    /**
     * Generate a factor key KEY_FACTOR_BIOMETRY from KEY_ACTIVATION_SECRET using KDF.
     *
     * @see KeyFactory#deriveKeyAuthenticationCodeBiometry(SecretKey)
     * @param keyActivationSecret Activation secret key KEY_ACTIVATION_SECRET.
     * @return An instance of factor key KEY_FACTOR_BIOMETRY.
     * @throws GenericCryptoException In case key derivation fails.
     */
    public SecretKey generateClientBiometryFactorKey(SecretKey keyActivationSecret) throws GenericCryptoException {
        return KeyFactory.deriveKeyAuthenticationCodeBiometry(keyActivationSecret);
    }

    /**
     * Generate a factor key KEY_FACTOR_KNOWLEDGE from KEY_ACTIVATION_SECRET using KDF.
     *
     * @see KeyFactory#deriveKeyAuthenticationCodeKnowledge(SecretKey)
     * @param keyActivationSecret Activation secret key KEY_ACTIVATION_SECRET.
     * @return An instance of factor key KEY_FACTOR_KNOWLEDGE.
     * @throws GenericCryptoException In case key derivation fails.
     */
    public SecretKey generateClientKnowledgeFactorKey(SecretKey keyActivationSecret) throws GenericCryptoException {
        return KeyFactory.deriveKeyAuthenticationCodeKnowledge(keyActivationSecret);
    }

    /**
     * Generate a factor key KEY_FACTOR_POSSESSION from KEY_ACTIVATION_SECRET using KDF.
     *
     * @see KeyFactory#deriveKeyAuthenticationCodePossession(SecretKey) (SecretKey)
     * @param keyActivationSecret Activation secret key KEY_ACTIVATION_SECRET.
     * @return An instance of factor key KEY_FACTOR_POSSESSION.
     * @throws GenericCryptoException In case key derivation fails.
     */
    public SecretKey generateClientPossessionFactorKey(SecretKey keyActivationSecret) throws GenericCryptoException {
        return KeyFactory.deriveKeyAuthenticationCodePossession(keyActivationSecret);
    }

}
