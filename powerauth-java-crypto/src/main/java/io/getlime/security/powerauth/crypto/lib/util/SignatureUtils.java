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

import com.google.common.base.Joiner;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.exception.CryptoProviderException;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for signature calculation and validation used both on client and server.
 *
 * @author Petr Dvorak
 *
 */
public class SignatureUtils {

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
            Signature ecdsa = Signature.getInstance("SHA256withECDSA", PowerAuthConfiguration.INSTANCE.getKeyConvertor().getProviderName());
            ecdsa.initSign(masterPrivateKey);
            ecdsa.update(bytes);
            return ecdsa.sign();
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new CryptoProviderException(ex.getMessage(), ex);
        } catch (SignatureException ex) {
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
            Signature ecdsa = Signature.getInstance("SHA256withECDSA", PowerAuthConfiguration.INSTANCE.getKeyConvertor().getProviderName());
            ecdsa.initVerify(masterPublicKey);
            ecdsa.update(signedBytes);
            return ecdsa.verify(signature);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new CryptoProviderException(ex.getMessage(), ex);
        } catch (SignatureException ex) {
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Compute decimal formatted PowerAuth signature for given data using a secret signature keys and counter byte array.
     *
     * @param data Data to be signed.
     * @param signatureKeys Keys for computing the signature.
     * @param ctrData Counter byte array / derived key index.
     * @return Decimal formatted PowerAuth signature for given data.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private String computePowerAuthDecimalSignature(byte[] data, List<SecretKey> signatureKeys, byte[] ctrData) throws GenericCryptoException, CryptoProviderException {
        // Prepare holder for signature components
        final String[] signatureStringComponents = new String[signatureKeys.size()];
        // Compute signature components
        final List<byte[]> signatureComponents = computePowerAuthSignatureComponents(data, signatureKeys, ctrData);
        // Convert byte components into decimal signature
        for (int i = 0; i < signatureComponents.size(); i++) {
            final byte[] signatureComponent = signatureComponents.get(i);
            int index = signatureComponent.length - 4;
            int number = (ByteBuffer.wrap(signatureComponent).getInt(index) & 0x7FFFFFFF) % (int) (Math.pow(10, PowerAuthConfiguration.SIGNATURE_DECIMAL_LENGTH));
            signatureStringComponents[i] = String.format("%0" + PowerAuthConfiguration.SIGNATURE_DECIMAL_LENGTH + "d", number);
        }
        // Join components with dash.
        return Joiner.on("-").join(signatureStringComponents);
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
        return BaseEncoding.base64().encode(signatureBytes);
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
        final List<byte[]> signatureComponents = new ArrayList<byte[]>();

        final CryptoProviderUtil keyConverter = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

        for (int i = 0; i < signatureKeys.size(); i++) {
            final byte[] signatureKey = keyConverter.convertSharedSecretKeyToBytes(signatureKeys.get(i));
            byte[] derivedKey = hmac.hash(signatureKey, ctrData);

            for (int j = 0; j < i; j++) {
                byte[] signatureKeyInner = keyConverter.convertSharedSecretKeyToBytes(signatureKeys.get(j + 1));
                byte[] derivedKeyInner = hmac.hash(signatureKeyInner, ctrData);
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
     * @param format Format of signature to produce.
     * @return PowerAuth signature for given data.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public String computePowerAuthSignature(byte[] data, List<SecretKey> signatureKeys, byte[] ctrData, PowerAuthSignatureFormat format) throws GenericCryptoException, CryptoProviderException {
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
        switch (format) {
            case BASE64:
                return computePowerAuthBase64Signature(data, signatureKeys, ctrData);
            case DECIMAL:
                return computePowerAuthDecimalSignature(data, signatureKeys, ctrData);
            default:
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
     * @param format Format in which signature will be validated.
     * @return Return "true" if signature matches, "false" otherwise.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean validatePowerAuthSignature(byte[] data, String signature, List<SecretKey> signatureKeys, byte[] ctrData, PowerAuthSignatureFormat format) throws GenericCryptoException, CryptoProviderException {
        return signature.equals(computePowerAuthSignature(data, signatureKeys, ctrData, format));
    }

}
