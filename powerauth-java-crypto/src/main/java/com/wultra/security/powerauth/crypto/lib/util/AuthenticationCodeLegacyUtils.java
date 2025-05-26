package com.wultra.security.powerauth.crypto.lib.util;

import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.config.DecimalAuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Utility class for calculating PowerAuth authentication codes (V3).
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 */
public class AuthenticationCodeLegacyUtils {

    /**
     * Compute decimal formatted PowerAuth authentication code for given data using a secret factor keys and counter byte array.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
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
    private String computeAuthDecimalCode(byte[] data, List<SecretKey> factorKeys, byte[] ctrData, Integer length) throws GenericCryptoException, CryptoProviderException {
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
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param data Data to be signed.
     * @param factorKeys Factor keys used for the computation.
     * @param ctrData Counter byte array / derived key index.
     * @return Base64 formatted PowerAuth authentication code for given data.
     * @throws GenericCryptoException In case authentication code computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private String computeAuthBase64Code(byte[] data, List<SecretKey> factorKeys, byte[] ctrData) throws GenericCryptoException, CryptoProviderException {
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

    /**
     * Compute PowerAuth authentication code for given data using a secret factor keys and counter byte array. The authentication code is returned
     * in form of list of binary components, where each item in returned array contains an appropriate factor. The returned
     * array must be then post-processed into the decimal, or Base64 format.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param data Data to be signed.
     * @param factorKeys Factor keys used for the computation.
     * @param ctrData Counter byte array / derived key index.
     * @return List with binary authentication code components.
     * @throws GenericCryptoException In case authentication code computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private List<byte[]> computeAuthCodeComponents(byte[] data, List<SecretKey> factorKeys, byte[] ctrData) throws GenericCryptoException, CryptoProviderException {
        // Prepare a hash
        final HMACHashUtilities hmac = new HMACHashUtilities();

        // Prepare array for authentication code binary components.
        final List<byte[]> components = new ArrayList<>();

        final KeyConvertor keyConvertor = new KeyConvertor();

        for (int i = 0; i < factorKeys.size(); i++) {
            final byte[] authenticationCodeKey = keyConvertor.convertSharedSecretKeyToBytes(factorKeys.get(i));
            byte[] derivedKey = hmac.hash(authenticationCodeKey, ctrData);

            for (int j = 0; j < i; j++) {
                final byte[] keyInner = keyConvertor.convertSharedSecretKeyToBytes(factorKeys.get(j + 1));
                final byte[] derivedKeyInner = hmac.hash(keyInner, ctrData);
                derivedKey = hmac.hash(derivedKeyInner, derivedKey);
            }

            final byte[] authenticationCodeBytes = hmac.hash(derivedKey, data);
            // Test whether calculated authentication code has sufficient amount of bytes.
            if (authenticationCodeBytes.length < PowerAuthConfiguration.AUTH_CODE_BINARY_LENGTH) { // assert
                throw new IndexOutOfBoundsException();
            }
            components.add(authenticationCodeBytes);
        }

        return components;
    }

    /**
     * Compute PowerAuth authentication code for given data using a secret factor keys and counter byte array.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
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
                return computeAuthBase64Code(data, factorKeys, ctrData);
            }
            case DECIMAL -> {
                final Integer len = ((DecimalAuthenticationCodeConfiguration) configuration).getLength();
                return computeAuthDecimalCode(data, factorKeys, ctrData, len);
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
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param data Data that were signed.
     * @param authenticationCode Authentication code.
     * @param factorKeys Factor keys used for the validation.
     * @param ctrData Counter data.
     * @param configuration Format in which authentication code will be validated and parameters for the validation.
     * @return Return "true" if authentication code matches, "false" otherwise.
     * @throws GenericCryptoException In case authentication code computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean validatePowerAuthCode(byte[] data, String authenticationCode, List<SecretKey> factorKeys, byte[] ctrData, AuthenticationCodeConfiguration configuration) throws GenericCryptoException, CryptoProviderException {
        return authenticationCode.equals(computeAuthCode(data, factorKeys, ctrData, configuration));
    }

}
