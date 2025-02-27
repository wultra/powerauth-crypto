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

package com.wultra.security.powerauth.crypto.lib.util;

import com.wultra.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.Kmac;
import lombok.NoArgsConstructor;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Utility class for PowerAuth authentication code calculation and validation used both on client and server.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@NoArgsConstructor
public class AuthenticationCodeUtils {

    private static final byte[] KMAC_AUTH_CODE_CUSTOM_BYTES = "PA4CODE".getBytes(StandardCharsets.UTF_8);

    /**
     * Compute online authentication code for given data using a secret factor keys and counter byte array.
     *
     * @param data Data to be signed.
     * @param factorKeys Keys for computing the authentication code.
     * @param ctrData Counter byte array / derived key index.
     * @return Online authentication code for given data.
     * @throws GenericCryptoException In case authentication code computation fails.
     */
    public String computeOnlineAuthCode(byte[] data, List<SecretKey> factorKeys, byte[] ctrData) throws GenericCryptoException {
        final List<byte[]> components = computeAuthCodeComponents(data, factorKeys, ctrData);
        final byte[] authCodeBytes = new byte[factorKeys.size() * PowerAuthConfiguration.AUTH_CODE_BINARY_LENGTH];
        for (int i = 0; i < components.size(); i++) {
            final byte[] component = components.get(i);
            ByteUtils.copy(component, 0, authCodeBytes, i * PowerAuthConfiguration.AUTH_CODE_BINARY_LENGTH, PowerAuthConfiguration.AUTH_CODE_BINARY_LENGTH);
        }
        return Base64.getEncoder().encodeToString(authCodeBytes);
    }

    /**
     * Compute offline authentication code for given data using a secret factor keys and counter byte array.
     *
     * @param data Data to be signed.
     * @param factorKeys Keys for computing the authentication code.
     * @param ctrData Counter byte array / derived key index.
     * @return Offline authentication code for given data.
     * @throws GenericCryptoException In case authentication code computation fails.
     */
    public String computeOfflineAuthCode(byte[] data, List<SecretKey> factorKeys, byte[] ctrData) throws GenericCryptoException {
        final List<byte[]> components = computeAuthCodeComponents(data, factorKeys, ctrData);
        final String[] authCodes = new String[factorKeys.size()];
        for (int i = 0; i < components.size(); i++) {
            final byte[] component = components.get(i);
            final int index = component.length - 4;
            final int number = (ByteBuffer.wrap(component).getInt(index) & 0x7FFFFFFF) % (int) Math.pow(10, PowerAuthConfiguration.AUTH_CODE_DECIMAL_LENGTH);
            authCodes[i] = String.format("%0" + PowerAuthConfiguration.AUTH_CODE_DECIMAL_LENGTH + "d", number);
        }
        return String.join("-", authCodes);
    }

    /**
     * Compute PowerAuth authentication code components for given data using a secret factor keys and counter byte array. The code is returned
     * in form of list of binary components, where each item in returned array contains an appropriate factor. The returned
     * array must be then post-processed into the decimal, or Base64 format.
     *
     * @param data Data to be signed.
     * @param factorKeys Keys for computing the authentication code.
     * @param ctrData Counter byte array / derived key index.
     * @return List with binary authentication code components.
     * @throws GenericCryptoException In case authentication code computation fails.
     */
    private List<byte[]> computeAuthCodeComponents(byte[] data, List<SecretKey> factorKeys, byte[] ctrData) throws GenericCryptoException {
        if (data == null) {
            throw new GenericCryptoException("Missing data for authentication code calculation");
        }
        if (factorKeys == null || factorKeys.isEmpty() || factorKeys.size() > PowerAuthConfiguration.MAX_FACTOR_KEYS_COUNT) {
            throw new GenericCryptoException("Invalid factor keys for authentication code calculation");
        }
        if (ctrData == null) {
            throw new GenericCryptoException("Missing counter data for authentication code calculation");
        }
        if (ctrData.length != PowerAuthConfiguration.AUTH_CODE_COUNTER_LENGTH) {
            throw new GenericCryptoException("Invalid length of counter data");
        }
        final List<byte[]> components = new ArrayList<>();
        for (int i = 0; i < factorKeys.size(); i++) {
            final SecretKey key = factorKeys.get(0);
            byte[] keyDerived = Kmac.kmac256(key, ctrData, KMAC_AUTH_CODE_CUSTOM_BYTES);
            for (int j = 0; j < i; j++) {
                final SecretKey keyInner = factorKeys.get(j + 1);
                final byte[] keyDerivedCurrent = Kmac.kmac256(keyInner, ctrData, KMAC_AUTH_CODE_CUSTOM_BYTES);
                keyDerived = Kmac.kmac256(keyDerivedCurrent, keyDerived, KMAC_AUTH_CODE_CUSTOM_BYTES);
            }
            final byte[] component = Kmac.kmac256(keyDerived, data, KMAC_AUTH_CODE_CUSTOM_BYTES, PowerAuthConfiguration.AUTH_CODE_BINARY_LENGTH);
            components.add(component);
        }
        return components;
    }

}
