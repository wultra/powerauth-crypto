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

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

/**
 * Key convertor for conversion of symmetric and asymmetric keys.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class KeyConvertor {

    private static final Logger logger = LoggerFactory.getLogger(KeyConvertor.class);

    private final PublicKeyValidator publicKeyValidator = new PublicKeyValidator();

    /**
     * Converts an EC public key to a byte array by encoding Q point parameter (W in Java Security).
     *
     * @param publicKey An EC public key to be converted.
     * @return A byte array representation of the EC public key.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     */
    public byte[] convertPublicKeyToBytes(PublicKey publicKey) throws CryptoProviderException {
        // Extract public key point
        ECPoint ecPoint = ((ECPublicKey) publicKey).getW();
        // Create EC point using Bouncy Castle library
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        if (ecSpec == null) { // can happen with incorrectly initialized crypto provider.
            throw new CryptoProviderException("Crypto provider does not support the secp256r1 curve");
        }
        org.bouncycastle.math.ec.ECPoint point = ecSpec.getCurve().createPoint(ecPoint.getAffineX(), ecPoint.getAffineY());
        // Extract byte[] uncompressed representation
        return point.getEncoded(false);
    }

    /**
     * Converts byte array to an EC public key, by decoding the Q point (W in Java Security).
     * parameter.
     *
     * @param keyBytes Bytes to be converted to EC public key.
     * @return An instance of the EC public key on success, or null on failure.
     * @throws InvalidKeySpecException When provided bytes are not a correct key
     *                                 representation.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     * @throws GenericCryptoException When public key is invalid.
     */
    public PublicKey convertBytesToPublicKey(byte[] keyBytes) throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException {
        try {
            // Decode EC point using Bouncy Castle and extract its coordinates
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            if (ecSpec == null) { // can happen with incorrectly initialized crypto provider.
                throw new CryptoProviderException("Crypto provider does not support the secp256r1 curve");
            }
            org.bouncycastle.math.ec.ECPoint point = ecSpec.getCurve().decodePoint(keyBytes);
            publicKeyValidator.validate(ecSpec.getCurve(), point);

            BigInteger x = point.getAffineXCoord().toBigInteger();
            BigInteger y = point.getAffineYCoord().toBigInteger();

            // Generate public key using Java security API
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
            ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(new ECPoint(x, y), ecParameterSpec);
            return KeyFactory.getInstance("EC", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME).generatePublic(ecPublicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException | NoSuchProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        } catch (IllegalArgumentException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Converts provided byte array representing X coordinate of an EC public key.
     *
     * @param xBytes X coordinate.
     * @param yBytes Y coordinate.
     * @return Public key with provided coordinates.
     * @throws InvalidKeySpecException When provided bytes are not a correct key representation.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     * @throws GenericCryptoException  When public key is invalid.
     */
    public PublicKey convertPointBytesToPublicKey(byte[] xBytes, byte[] yBytes) throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException {
        try {
            // Make sure the values are interpreted as positive integer.
            final BigInteger x = new BigInteger(1, xBytes);
            final BigInteger y = new BigInteger(1, yBytes);

            // Validate the point is correct
            final ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            if (ecSpec == null) { // can happen with incorrectly initialized crypto provider.
                throw new CryptoProviderException("Crypto provider does not support the secp256r1 curve");
            }
            final org.bouncycastle.math.ec.ECPoint point = ecSpec.getCurve().createPoint(x, y);
            publicKeyValidator.validate(ecSpec.getCurve(), point);

            // Generate public key using Java security API
            final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            parameters.init(new ECGenParameterSpec("secp256r1"));
            final ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

            final ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(new ECPoint(x, y), ecParameterSpec);
            return KeyFactory.getInstance("EC", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME).generatePublic(ecPublicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException | NoSuchProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        } catch (IllegalArgumentException ex) {
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Converts an EC private key to bytes by encoding the D number parameter (S in Java Security).
     *
     * @param privateKey An EC private key to be converted to bytes.
     * @return A byte array containing the representation of the EC private key.
     */
    public byte[] convertPrivateKeyToBytes(PrivateKey privateKey) {
        // Private key is stored including the sign bit as regular Java BigInteger representation
        return ((ECPrivateKey) privateKey).getS().toByteArray();
    }

    /**
     * Convert a byte array to an EC private key by decoding the D number parameter (S in Java Security).
     *
     * @param keyBytes Bytes to be converted to the EC private key.
     * @return An instance of EC private key decoded from the input bytes.
     * @throws InvalidKeySpecException The provided key bytes are not a valid EC
     *                                 private key.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     */
    public PrivateKey convertBytesToPrivateKey(byte[] keyBytes) throws InvalidKeySpecException, CryptoProviderException {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
            // Private key is stored including the sign bit as regular Java BigInteger representation
            ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(new BigInteger(keyBytes), ecParameterSpec);
            return KeyFactory.getInstance("EC", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME).generatePrivate(ecPrivateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException | NoSuchProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        }
    }

    /**
     * Converts a shared secret key (usually used for AES based operations) to a
     * byte array.
     *
     * @param sharedSecretKey A shared key to be converted to bytes.
     * @return A byte array representation of the shared secret key.
     */
    public byte[] convertSharedSecretKeyToBytes(SecretKey sharedSecretKey) {
        return sharedSecretKey.getEncoded();
    }

    /**
     * Converts a byte array to the secret shared key (usually used for AES
     * based operations).
     *
     * @param bytesSecretKey Bytes representing the shared key.
     * @return An instance of the secret key by decoding from provided bytes.
     */
    public SecretKey convertBytesToSharedSecretKey(byte[] bytesSecretKey) {
        return new SecretKeySpec(bytesSecretKey, "AES");
    }

}
