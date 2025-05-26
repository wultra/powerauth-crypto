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
package com.wultra.security.powerauth.crypto.server.v4.keyfactory;

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyFactory;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.List;


/**
 * Key factory used on server side to generate PowerAuth related keys (V4).
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PowerAuthServerKeyFactory {

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
            final SecretKey factorKey = generatePossessionFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
        } else if (powerAuthCodeType.equals(PowerAuthCodeType.KNOWLEDGE)) {
            final SecretKey factorKey = generateKnowledgeFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
        } else if (powerAuthCodeType.equals(PowerAuthCodeType.BIOMETRY)) {
            final SecretKey factorKey = generateBiometryFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_KNOWLEDGE)) {
            SecretKey factorKey = generatePossessionFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
            factorKey = generateKnowledgeFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_BIOMETRY)) {
            SecretKey factorKey = generatePossessionFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
            factorKey = generateBiometryFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
        } else if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY)) {
            SecretKey factorKey = generatePossessionFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
            factorKey = generateKnowledgeFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);
            factorKey = generateBiometryFactorKey(keyActivationSecret);
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
    public SecretKey generateBiometryFactorKey(SecretKey keyActivationSecret) throws GenericCryptoException {
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
    public SecretKey generateKnowledgeFactorKey(SecretKey keyActivationSecret) throws GenericCryptoException {
        return KeyFactory.deriveKeyAuthenticationCodeKnowledge(keyActivationSecret);
    }

    /**
     * Generate a factor key KEY_FACTOR_POSSESSION from KEY_ACTIVATION_SECRET using KDF.
     *
     * @see KeyFactory#deriveKeyAuthenticationCodePossession(SecretKey)
     * @param keyActivationSecret Activation secret key KEY_ACTIVATION_SECRET.
     * @return An instance of factor key KEY_FACTOR_POSSESSION.
     * @throws GenericCryptoException In case key derivation fails.
     */
    public SecretKey generatePossessionFactorKey(SecretKey keyActivationSecret) throws GenericCryptoException {
        return KeyFactory.deriveKeyAuthenticationCodePossession(keyActivationSecret);
    }

    /**
     * Generate a factor key KEY_MAC_GET_ACT_TEMP_KEY from KEY_ACTIVATION_SECRET using KDF.
     *
     * @see KeyFactory#deriveKeyMacGetActTempKey(SecretKey)
     * @param keyActivationSecret Activation secret key KEY_ACTIVATION_SECRET.
     * @return An instance of key KEY_MAC_GET_ACT_TEMP_KEY.
     * @throws GenericCryptoException In case key derivation fails.
     */
    public SecretKey generateKeyMacGetActTempKey(SecretKey keyActivationSecret) throws GenericCryptoException {
        return KeyFactory.deriveKeyMacGetActTempKey(keyActivationSecret);
    }

    /**
     * Generate a factor key KEY_MAC_STATUS from KEY_ACTIVATION_SECRET using KDF.
     *
     * @see KeyFactory#deriveKeyMacStatus(SecretKey) (SecretKey)
     * @param keyActivationSecret Activation secret key KEY_ACTIVATION_SECRET.
     * @return An instance of key KEY_MAC_STATUS.
     * @throws GenericCryptoException In case key derivation fails.
     */
    public SecretKey generateKeyMacStatus(SecretKey keyActivationSecret) throws GenericCryptoException {
        return KeyFactory.deriveKeyMacStatus(keyActivationSecret);
    }

    /**
     * Generate a factor key KEY_MAC_CTR_DATA from KEY_ACTIVATION_SECRET using KDF.
     *
     * @see KeyFactory#deriveKeyMacCtrData(SecretKey)
     * @param keyActivationSecret Activation secret key KEY_ACTIVATION_SECRET.
     * @return An instance of key KEY_MAC_CTR_DATA.
     * @throws GenericCryptoException In case key derivation fails.
     */
    public SecretKey generateKeyMacCtrData(SecretKey keyActivationSecret) throws GenericCryptoException {
        return KeyFactory.deriveKeyMacCtrData(keyActivationSecret);
    }

    /**
     * Generate a factor key KEY_E2EE_SHARED_INFO2 from KEY_ACTIVATION_SECRET using KDF.
     *
     * @see KeyFactory#deriveKeyMacStatus(SecretKey) (SecretKey)
     * @param keyActivationSecret Activation secret key KEY_ACTIVATION_SECRET.
     * @return An instance of key KEY_E2EE_SHARED_INFO2.
     * @throws GenericCryptoException In case key derivation fails.
     */
    public SecretKey generateSharedInfo2Key(SecretKey keyActivationSecret) throws GenericCryptoException {
        return KeyFactory.deriveKeyE2eeSharedInfo2(keyActivationSecret);
    }

}
