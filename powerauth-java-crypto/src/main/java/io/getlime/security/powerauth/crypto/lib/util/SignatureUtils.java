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
package io.getlime.security.powerauth.crypto.lib.util;

import io.getlime.security.powerauth.crypto.lib.config.DecimalSignatureConfiguration;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.config.SignatureConfiguration;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
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
     *
     * @param bytes Bytes to be signed.
     * @param masterPrivateKey Private key for computing the signature.
     * @return Signature for given data.
     * @throws InvalidKeyException In case invalid key was provided.
     * @throws GenericCryptoException In case signature calculation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] computeECDSASignature(byte[] bytes, PrivateKey masterPrivateKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        try {
            final Signature ecdsa = Signature.getInstance("SHA256withECDSA", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
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
     * Compute ECDSA signature of given bytes with a private key, using a provided instance of SecureRandom.
     *
     * @param bytes Bytes to be signed.
     * @param masterPrivateKey Private key for computing the signature.
     * @param secureRandom Secure random instance.
     * @return Signature for given data.
     * @throws InvalidKeyException In case invalid key was provided.
     * @throws GenericCryptoException In case signature calculation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] computeECDSASignature(byte[] bytes, PrivateKey masterPrivateKey, SecureRandom secureRandom) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        try {
            final Signature ecdsa = Signature.getInstance("SHA256withECDSA", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
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
     *
     * @param signedBytes Bytes that are signed.
     * @param signature Signature of the bytes.
     * @param masterPublicKey Public key for validating the signature.
     * @return Returns "true" if signature matches, "false" otherwise.
     * @throws InvalidKeyException In case invalid key was provided.
     * @throws GenericCryptoException In case signature calculation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean validateECDSASignature(byte[] signedBytes, byte[] signature, PublicKey masterPublicKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        try {
            final Signature ecdsa = Signature.getInstance("SHA256withECDSA", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
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
     * Compute decimal formatted PowerAuth signature for given data using a secret signature keys and counter byte array.
     *
     * @param data Data to be signed.
     * @param signatureKeys Keys for computing the signature.
     * @param ctrData Counter byte array / derived key index.
     * @param length Required length of the factor related signature component (i.e, if length is 4, then 2FA will
     *               have 8 digits). Minimal allowed non-null value is 4. Maximum allowed value is 8. If the value
     *               is null, the default system value (8) is used.
     * @return Decimal formatted PowerAuth signature for given data.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private String computePowerAuthDecimalSignature(byte[] data, List<SecretKey> signatureKeys, byte[] ctrData, Integer length) throws GenericCryptoException, CryptoProviderException {
        // Determine the length of the signature component, validate length
        final int signatureDecimalLength;
        if (length != null) {
            if (length < 4) {
                throw new CryptoProviderException("Length must be at least 4, provided: " + length);
            }
            if (length > 8) {
                throw new CryptoProviderException("Length must be less or equal to 8, provided: " + length);
            }
            signatureDecimalLength = length;
        } else {
            signatureDecimalLength = PowerAuthConfiguration.SIGNATURE_DECIMAL_LENGTH;
        }
        // Prepare holder for signature components
        final String[] signatureStringComponents = new String[signatureKeys.size()];
        // Compute signature components
        final List<byte[]> signatureComponents = computePowerAuthSignatureComponents(data, signatureKeys, ctrData);
        // Convert byte components into decimal signature
        for (int i = 0; i < signatureComponents.size(); i++) {
            final byte[] signatureComponent = signatureComponents.get(i);
            final int index = signatureComponent.length - 4;
            final int number = (ByteBuffer.wrap(signatureComponent).getInt(index) & 0x7FFFFFFF) % (int) (Math.pow(10, signatureDecimalLength));
            signatureStringComponents[i] = String.format("%0" + signatureDecimalLength + "d", number);
        }
        // Join components with dash.
        return String.join("-", signatureStringComponents);
    }

    /**
     * Compute Base64 formatted PowerAuth signature for given data using a secret signature keys and counter byte array.
     *
     * @param data Data to be signed.
     * @param signatureKeys Keys for computing the signature.
     * @param ctrData Counter byte array / derived key index.
     * @return Base64 formatted PowerAuth signature for given data.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private String computePowerAuthBase64Signature(byte[] data, List<SecretKey> signatureKeys, byte[] ctrData) throws GenericCryptoException, CryptoProviderException {
        // Prepare array of bytes for a complete signature
        final byte[] signatureBytes = new byte[signatureKeys.size() * PowerAuthConfiguration.SIGNATURE_BINARY_LENGTH];
        // Compute signature components
        final List<byte[]> signatureComponents = computePowerAuthSignatureComponents(data, signatureKeys, ctrData);
        // Convert signature components into one Base64 encoded signature string
        for (int i = 0; i < signatureComponents.size(); i++) {
            final byte[] signatureComponent = signatureComponents.get(i);
            final int sourceOffset = signatureComponent.length - PowerAuthConfiguration.SIGNATURE_BINARY_LENGTH;
            final int destinationOffset = i * PowerAuthConfiguration.SIGNATURE_BINARY_LENGTH;
            System.arraycopy(signatureComponent, sourceOffset, signatureBytes, destinationOffset, PowerAuthConfiguration.SIGNATURE_BINARY_LENGTH);
        }
        // Finally, convert bytes into one Base64 string
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    /**
     * Compute PowerAuth signature for given data using a secret signature keys and counter byte array. The signature is returned
     * in form of list of binary components, where each item in returned array contains an appropriate signature factor. The returned
     * array must be then post-processed into the decimal, or Base64 format.
     *
     * @param data Data to be signed.
     * @param signatureKeys Keys for computing the signature.
     * @param ctrData Counter byte array / derived key index.
     * @return List with binary signature components.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private List<byte[]> computePowerAuthSignatureComponents(byte[] data, List<SecretKey> signatureKeys, byte[] ctrData) throws GenericCryptoException, CryptoProviderException {
        // Prepare a hash
        final HMACHashUtilities hmac = new HMACHashUtilities();

        // Prepare array for signature binary components.
        final List<byte[]> signatureComponents = new ArrayList<>();

        final KeyConvertor keyConvertor = new KeyConvertor();

        for (int i = 0; i < signatureKeys.size(); i++) {
            final byte[] signatureKey = keyConvertor.convertSharedSecretKeyToBytes(signatureKeys.get(i));
            byte[] derivedKey = hmac.hash(signatureKey, ctrData);

            for (int j = 0; j < i; j++) {
                final byte[] signatureKeyInner = keyConvertor.convertSharedSecretKeyToBytes(signatureKeys.get(j + 1));
                final byte[] derivedKeyInner = hmac.hash(signatureKeyInner, ctrData);
                derivedKey = hmac.hash(derivedKeyInner, derivedKey);
            }

            final byte[] signatureBytes = hmac.hash(derivedKey, data);
            // Test whether calculated signature has sufficient amount of bytes.
            if (signatureBytes.length < PowerAuthConfiguration.SIGNATURE_BINARY_LENGTH) { // assert
                throw new IndexOutOfBoundsException();
            }
            signatureComponents.add(signatureBytes);
        }

        return signatureComponents;
    }

    /**
     * Compute PowerAuth signature for given data using a secret signature keys and counter byte array.
     *
     * @param data Data to be signed.
     * @param signatureKeys Keys for computing the signature.
     * @param ctrData Counter byte array / derived key index.
     * @param configuration Format of signature to produce and parameters for the signature.
     * @return PowerAuth signature for given data.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public String computePowerAuthSignature(byte[] data, List<SecretKey> signatureKeys, byte[] ctrData, SignatureConfiguration configuration) throws GenericCryptoException, CryptoProviderException {
        if (signatureKeys == null) {
            throw new GenericCryptoException("Missing signatureKeys parameter");
        }
        if (ctrData == null) {
            throw new GenericCryptoException("Missing ctrData parameter");
        }
        if (signatureKeys.isEmpty() || signatureKeys.size() > PowerAuthConfiguration.MAX_SIGNATURE_KEYS_COUNT) {
            throw new GenericCryptoException("Wrong number of signature keys");
        }
        if (ctrData.length != PowerAuthConfiguration.SIGNATURE_COUNTER_LENGTH) {
            throw new GenericCryptoException("Invalid length of signature counter");
        }
        switch (configuration.getSignatureFormat()) {
            case BASE64 -> {
                return computePowerAuthBase64Signature(data, signatureKeys, ctrData);
            }
            case DECIMAL -> {
                final Integer len = ((DecimalSignatureConfiguration) configuration).getLength();
                return computePowerAuthDecimalSignature(data, signatureKeys, ctrData, len);
            }
            default ->
                throw new GenericCryptoException("Unsupported format of PowerAuth signature.");
        }
    }

    /**
     * Validate the PowerAuth signature for given data using provided keys.
     *
     * @param data Data that were signed.
     * @param signature Data signature.
     * @param signatureKeys Keys for signature validation.
     * @param ctrData Counter data.
     * @param configuration Format in which signature will be validated and parameters for the validation.
     * @return Return "true" if signature matches, "false" otherwise.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean validatePowerAuthSignature(byte[] data, String signature, List<SecretKey> signatureKeys, byte[] ctrData, SignatureConfiguration configuration) throws GenericCryptoException, CryptoProviderException {
        return signature.equals(computePowerAuthSignature(data, signatureKeys, ctrData, configuration));
    }

}
