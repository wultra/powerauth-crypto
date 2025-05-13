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
package com.wultra.security.powerauth.crypto.lib.v4.authentication;

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyFactory;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.List;


/**
 * Key factory used on server side to generate PowerAuth authentication related keys.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class AuthenticationKeyFactory {

    /**
     * Generate a list with authentication code keys for given authentication code type and master secret
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param powerAuthCodeType Requested authentication code type
     * @param keyActivationSecret Activation shared secret key.
     * @return List with keys constructed from activation shared secret key that are needed to get
     * requested authentication code type.
     * @throws InvalidKeyException In case activation shared secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public List<SecretKey> keysForAuthenticationCodeType(PowerAuthCodeType powerAuthCodeType, SecretKey keyActivationSecret) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {

        List<SecretKey> factorKeys = new ArrayList<>();

        if (powerAuthCodeType == null) {
            return factorKeys;
        }

        if (powerAuthCodeType.equals(PowerAuthCodeType.POSSESSION)) {

            SecretKey factorKey = generatePossessionFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.KNOWLEDGE)) {

            SecretKey factorKey = generateKnowledgeFactorKey(keyActivationSecret);
            factorKeys.add(factorKey);

        } else if (powerAuthCodeType.equals(PowerAuthCodeType.BIOMETRY)) {

            SecretKey factorKey = generateBiometryFactorKey(keyActivationSecret);
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
     * Generate a factor key {@code KEY_AUTHENTICATION_CODE_BIOMETRY} from {@code KEY_ACTIVATION_SECRET} using KDF.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param keyActivationSecret Activation shared secret key.
     * @return An instance of factor key {@code KEY_AUTHENTICATION_CODE_BIOMETRY}.
     * @throws GenericCryptoException In case key derivation fails.
     */
    public SecretKey generateBiometryFactorKey(SecretKey keyActivationSecret) throws GenericCryptoException {
        return KeyFactory.deriveKeyAuthenticationCodeBiometry(keyActivationSecret);
    }

    /**
     * Generate a factor key {@code KEY_AUTHENTICATION_CODE_KNOWLEDGE} from {@code KEY_ACTIVATION_SECRET} using KDF.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param keyActivationSecret Activation shared secret key.
     * @return An instance of factor key {@code KEY_AUTHENTICATION_CODE_KNOWLEDGE}.
     * @throws GenericCryptoException In case key derivation fails.
     */
    public SecretKey generateKnowledgeFactorKey(SecretKey keyActivationSecret) throws GenericCryptoException {
        return KeyFactory.deriveKeyAuthenticationCodeKnowledge(keyActivationSecret);
    }

    /**
     * Generate a factor key {@code KEY_AUTHENTICATION_CODE_POSSESSION} from {@code KEY_ACTIVATION_SECRET} using KDF.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param keyActivationSecret Activation shared secret key.
     * @return An instance of factor key {@code KEY_AUTHENTICATION_CODE_POSSESSION}.
     * @throws GenericCryptoException In case key derivation fails.
     */
    public SecretKey generatePossessionFactorKey(SecretKey keyActivationSecret) throws GenericCryptoException {
        return KeyFactory.deriveKeyAuthenticationCodePossession(keyActivationSecret);
    }

}
