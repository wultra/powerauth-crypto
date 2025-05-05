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
package com.wultra.security.powerauth.crypto.lib.util;

import com.wultra.security.powerauth.crypto.lib.config.DecimalAuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Utility class for signature calculation and validation used both on client and server.
 *
 * @author Petr Dvorak
 *
 */
public class SignatureUtils {

    private static final Logger logger = LoggerFactory.getLogger(SignatureUtils.class);

    /**
     * Compute ECDSA signature of given bytes with a private key.
     * @deprecated use {@link #computeECDSASignature(EcCurve, byte[], PrivateKey)}
     *
     * @param bytes Bytes to be signed.
     * @param masterPrivateKey Private key for computing the signature.
     * @return Signature for given data.
     * @throws InvalidKeyException In case invalid key was provided.
     * @throws GenericCryptoException In case signature calculation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    @Deprecated
    public byte[] computeECDSASignature(byte[] bytes, PrivateKey masterPrivateKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return computeECDSASignature(EcCurve.P256, bytes, masterPrivateKey);
    }

    /**
     * Compute ECDSA signature of given bytes with a private key.
     * @deprecated use {@link #computeECDSASignature(EcCurve, byte[], PrivateKey, SecureRandom)}
     *
     * @param bytes Bytes to be signed.
     * @param masterPrivateKey Private key for computing the signature.
     * @param secureRandom Secure random instance.
     * @return Signature for given data.
     * @throws InvalidKeyException In case invalid key was provided.
     * @throws GenericCryptoException In case signature calculation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    @Deprecated
    public byte[] computeECDSASignature(byte[] bytes, PrivateKey masterPrivateKey, SecureRandom secureRandom) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return computeECDSASignature(EcCurve.P256, bytes, masterPrivateKey, secureRandom);
    }

    /**
     * Compute ECDSA signature of given bytes using SHA256withECDSA with a private key, using a provided instance of SecureRandom.
     *
     * @param curve EC curve to use.
     * @param bytes Bytes to be signed.
     * @param masterPrivateKey Private key for computing the signature.
     * @return Signature for given data.
     * @throws InvalidKeyException In case invalid key was provided.
     * @throws GenericCryptoException In case signature calculation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] computeECDSASignature(EcCurve curve, byte[] bytes, PrivateKey masterPrivateKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        try {
            final Signature ecdsa = Signature.getInstance(curve.getEcdsaAlgorithm(), PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            ecdsa.initSign(masterPrivateKey);
            ecdsa.update(bytes);
            return ecdsa.sign();
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            logger.warn("Calculating signature failed due to cryptographic provider issue: {}", ex.getMessage());
            logger.debug("Exception detail: ", ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        } catch (SignatureException ex) {
            logger.warn("Calculating signature failed due to configuration issue: {}", ex.getMessage());
            logger.debug("Exception detail: ", ex);
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Compute ECDSA signature of given bytes using SHA256withECDSA with a private key, using a provided instance of SecureRandom.
     *
     * @param curve EC curve to use.
     * @param bytes Bytes to be signed.
     * @param masterPrivateKey Private key for computing the signature.
     * @param secureRandom Secure random instance.
     * @return Signature for given data.
     * @throws InvalidKeyException In case invalid key was provided.
     * @throws GenericCryptoException In case signature calculation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] computeECDSASignature(EcCurve curve, byte[] bytes, PrivateKey masterPrivateKey, SecureRandom secureRandom) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        try {
            final Signature ecdsa = Signature.getInstance(curve.getEcdsaAlgorithm(), PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            ecdsa.initSign(masterPrivateKey, secureRandom);
            ecdsa.update(bytes);
            return ecdsa.sign();
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            logger.warn("Calculating signature failed due to cryptographic provider issue: {}", ex.getMessage());
            logger.debug("Exception detail: ", ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        } catch (SignatureException ex) {
            logger.warn("Calculating signature failed due to configuration issue: {}", ex.getMessage());
            logger.debug("Exception detail: ", ex);
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Validate an ECDSA signature against given data using a public key.
     * @deprecated use {@link #validateECDSASignature(EcCurve, byte[], byte[], PublicKey)}
     *
     * @param signedBytes Bytes that are signed.
     * @param signature Signature of the bytes.
     * @param masterPublicKey Public key for validating the signature.
     * @return Returns "true" if signature matches, "false" otherwise.
     * @throws InvalidKeyException In case invalid key was provided.
     * @throws GenericCryptoException In case signature calculation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    @Deprecated
    public boolean validateECDSASignature(byte[] signedBytes, byte[] signature, PublicKey masterPublicKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return this.validateECDSASignature(EcCurve.P256, signedBytes, signature, masterPublicKey);
    }

    /**
     * Validate an ECDSA signature using SHA256withECDSA against given data using a public key.
     *
     * @param curve EC curve to use.
     * @param signedBytes Bytes that are signed.
     * @param signature Signature of the bytes.
     * @param masterPublicKey Public key for validating the signature.
     * @return Returns "true" if signature matches, "false" otherwise.
     * @throws InvalidKeyException In case invalid key was provided.
     * @throws GenericCryptoException In case signature calculation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean validateECDSASignature(EcCurve curve, byte[] signedBytes, byte[] signature, PublicKey masterPublicKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        try {
            final Signature ecdsa = Signature.getInstance(curve.getEcdsaAlgorithm(), PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            ecdsa.initVerify(masterPublicKey);
            ecdsa.update(signedBytes);
            return ecdsa.verify(signature);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            logger.warn("Verifying signature failed due to cryptographic provider issue: {}", ex.getMessage());
            logger.debug("Exception detail: ", ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        } catch (SignatureException ex) {
            logger.warn("Verifying signature failed due to configuration issue: {}", ex.getMessage());
            logger.debug("Exception detail: ", ex);
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

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
    private String computePowerAuthDecimalCode(byte[] data, List<SecretKey> factorKeys, byte[] ctrData, Integer length) throws GenericCryptoException, CryptoProviderException {
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
        final List<byte[]> authCodeComponents = computePowerAuthCodeComponents(data, factorKeys, ctrData);
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
    private String computePowerAuthBase64Code(byte[] data, List<SecretKey> factorKeys, byte[] ctrData) throws GenericCryptoException, CryptoProviderException {
        // Prepare array of bytes for a complete authentication code
        final byte[] authenticationCodeBytes = new byte[factorKeys.size() * PowerAuthConfiguration.AUTH_CODE_BINARY_LENGTH];
        // Compute authentication code components
        final List<byte[]> authenticationCodeComponents = computePowerAuthCodeComponents(data, factorKeys, ctrData);
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
    private List<byte[]> computePowerAuthCodeComponents(byte[] data, List<SecretKey> factorKeys, byte[] ctrData) throws GenericCryptoException, CryptoProviderException {
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
    public String computePowerAuthCode(byte[] data, List<SecretKey> factorKeys, byte[] ctrData, AuthenticationCodeConfiguration configuration) throws GenericCryptoException, CryptoProviderException {
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
                return computePowerAuthBase64Code(data, factorKeys, ctrData);
            }
            case DECIMAL -> {
                final Integer len = ((DecimalAuthenticationCodeConfiguration) configuration).getLength();
                return computePowerAuthDecimalCode(data, factorKeys, ctrData, len);
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
        return authenticationCode.equals(computePowerAuthCode(data, factorKeys, ctrData, configuration));
    }

}
