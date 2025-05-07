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

import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.config.DecimalAuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
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
     * Compute PowerAuth authentication code for given data using a secret factor keys and counter byte array.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param data Data to be signed.
     * @param factorKeys Factor keys used for the computation.
     * @param ctrData Counter byte array / derived key index.
     * @param configuration Format of authentication code to produce and parameters for the authentication code.
     * @return PowerAuth authentication code for given data.
     * @throws GenericCryptoException In case authentication code computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public String computeAuthCode(byte[] data, List<SecretKey> factorKeys, byte[] ctrData, AuthenticationCodeConfiguration configuration) throws GenericCryptoException, CryptoProviderException {
        if (factorKeys == null) {
            throw new GenericCryptoException("Missing factorKeys parameter");
        }
        if (ctrData == null) {
            throw new GenericCryptoException("Missing ctrData parameter");
        }
        if (factorKeys.isEmpty() || factorKeys.size() > PowerAuthConfiguration.MAX_FACTOR_KEYS_COUNT) {
            throw new GenericCryptoException("Wrong number of factor keys");
        }
        if (ctrData.length != PowerAuthConfiguration.AUTH_CODE_BINARY_LENGTH) {
            throw new GenericCryptoException("Invalid length of counter");
        }
        switch (configuration.getAuthenticationCodeFormat()) {
            case BASE64 -> {
                return computeAuthCodeBase64(data, factorKeys, ctrData);
            }
            case DECIMAL -> {
                final Integer len = ((DecimalAuthenticationCodeConfiguration) configuration).getLength();
                return computeAuthCodeDecimal(data, factorKeys, ctrData, len);
            }
            default ->
                    throw new GenericCryptoException("Unsupported format of PowerAuth authentication code.");
        }
    }

    /**
     * Validate the PowerAuth authentication code for given data using provided keys.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param data Data that were signed.
     * @param authenticationCode Authentication code.
     * @param factorKeys Factor keys used for the validation.
     * @param ctrData Counter data.
     * @param powerAuthConfiguration Format of authentication code to produce and parameters for the authentication code.
     * @return Return "true" if authentication code matches, "false" otherwise.
     * @throws GenericCryptoException In case authentication code computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean validateAuthCode(byte[] data, String authenticationCode, List<SecretKey> factorKeys, byte[] ctrData, AuthenticationCodeConfiguration powerAuthConfiguration) throws GenericCryptoException, CryptoProviderException {
        return SideChannelUtils.constantTimeAreEqual(
                authenticationCode.getBytes(StandardCharsets.UTF_8),
                computeAuthCode(data, factorKeys, ctrData, powerAuthConfiguration).getBytes(StandardCharsets.UTF_8)
        );
    }

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

    /**
     * Compute decimal formatted PowerAuth authentication code for given data using a secret factor keys and counter byte array.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param data Data to be signed.
     * @param factorKeys Factor keys used for the computation.
     * @param ctrData Counter byte array / derived key index.
     * @param length Required length of the factor related authentication code component (i.e, if length is 4, then 2FA will
     *               have 8 digits). Minimal allowed non-null value is 4. Maximum allowed value is 8. If the value
     *               is null, the default system value (8) is used.
     * @return Decimal formatted PowerAuth authentication code for given data.
     * @throws GenericCryptoException In case authentication code computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private String computeAuthCodeDecimal(byte[] data, List<SecretKey> factorKeys, byte[] ctrData, Integer length) throws GenericCryptoException, CryptoProviderException {
        // Determine the length of the authentication code component, validate length
        final int decimalLength;
        if (length != null) {
            if (length < 4) {
                throw new CryptoProviderException("Length must be at least 4, provided: " + length);
            }
            if (length > 8) {
                throw new CryptoProviderException("Length must be less or equal to 8, provided: " + length);
            }
            decimalLength = length;
        } else {
            decimalLength = PowerAuthConfiguration.AUTH_CODE_DECIMAL_LENGTH;
        }
        // Prepare holder for authentication code components
        final String[] stringComponents = new String[factorKeys.size()];
        // Compute authentication code components
        final List<byte[]> authCodeComponents = computeAuthCodeComponents(data, factorKeys, ctrData);
        // Convert byte authentication code into decimal authentication code
        for (int i = 0; i < authCodeComponents.size(); i++) {
            final byte[] component = authCodeComponents.get(i);
            final int index = component.length - 4;
            final int number = (ByteBuffer.wrap(component).getInt(index) & 0x7FFFFFFF) % (int) (Math.pow(10, decimalLength));
            stringComponents[i] = String.format("%0" + decimalLength + "d", number);
        }
        // Join components with dash.
        return String.join("-", stringComponents);
    }

    /**
     * Compute Base64 formatted PowerAuth authentication code for given data using a secret factor keys and counter byte array.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param data Data to be signed.
     * @param factorKeys Factor keys used for the computation.
     * @param ctrData Counter byte array / derived key index.
     * @return Base64 formatted PowerAuth authentication code for given data.
     * @throws GenericCryptoException In case authentication code computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private String computeAuthCodeBase64(byte[] data, List<SecretKey> factorKeys, byte[] ctrData) throws GenericCryptoException, CryptoProviderException {
        // Prepare array of bytes for a complete authentication code
        final byte[] authenticationCodeBytes = new byte[factorKeys.size() * PowerAuthConfiguration.AUTH_CODE_BINARY_LENGTH];
        // Compute authentication code components
        final List<byte[]> authenticationCodeComponents = computeAuthCodeComponents(data, factorKeys, ctrData);
        // Convert authentication code components into one Base64 encoded string
        for (int i = 0; i < authenticationCodeComponents.size(); i++) {
            final byte[] component = authenticationCodeComponents.get(i);
            final int sourceOffset = component.length - PowerAuthConfiguration.AUTH_CODE_BINARY_LENGTH;
            final int destinationOffset = i * PowerAuthConfiguration.AUTH_CODE_BINARY_LENGTH;
            System.arraycopy(component, sourceOffset, authenticationCodeBytes, destinationOffset, PowerAuthConfiguration.AUTH_CODE_BINARY_LENGTH);
        }
        // Finally, convert bytes into one Base64 string
        return Base64.getEncoder().encodeToString(authenticationCodeBytes);
    }

}
