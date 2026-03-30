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

import com.wultra.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

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
     * @deprecated use {@link #convertBytesToPublicKey(EcCurve, byte[])}
     *
     * @param publicKey An EC public key to be converted.
     * @return A byte array representation of the EC public key.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     * @throws GenericCryptoException When public key is invalid.
     */
    @Deprecated
    public byte[] convertPublicKeyToBytes(PublicKey publicKey) throws CryptoProviderException, GenericCryptoException {
        return convertPublicKeyToBytes(EcCurve.P256, publicKey);
    }
    
    /**
     * Converts an EC public key to a byte array by encoding Q point parameter (W in Java Security).
     *
     * @param curve EC curve.
     * @param publicKey An EC public key to be converted.
     * @return A byte array representation of the EC public key.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     * @throws GenericCryptoException When public key is invalid.
     */
    public byte[] convertPublicKeyToBytes(EcCurve curve, PublicKey publicKey) throws CryptoProviderException, GenericCryptoException {
        if (!(publicKey instanceof ECPublicKey ecPublicKey)) {
            throw new GenericCryptoException("Public key to be converted is not an instance of ECPublicKey");
        }
        // Extract public key point
        final java.security.spec.ECPoint ecPoint = ecPublicKey.getW();
        // Create EC point using Bouncy Castle library
        final ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curve.getName());
        if (ecSpec == null) { // can happen with incorrectly initialized crypto provider.
            throw new CryptoProviderException("Crypto provider does not support EC curve " + curve.getName());
        }
        if (!(ecPublicKey.getParams().getOrder().equals(ecSpec.getN()))) {
            throw new GenericCryptoException("Public key EC curve order does not match EC curve order");
        }
        final ECPoint point = ecSpec.getCurve().createPoint(ecPoint.getAffineX(), ecPoint.getAffineY()).normalize();
        publicKeyValidator.validate(ecSpec.getCurve(), point);
        // Extract byte[] uncompressed representation
        return point.getEncoded(false);
    }

    /**
     * Converts byte array to an EC public key, by decoding the Q point (W in Java Security).
     * parameter.
     * @deprecated use {@link #convertBytesToPublicKey(EcCurve, byte[])}
     *
     * @param keyBytes Bytes to be converted to EC public key.
     * @return An instance of the EC public key on success, or null on failure.
     * @throws InvalidKeySpecException When provided bytes are not a correct key
     *                                 representation.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     * @throws GenericCryptoException When public key is invalid.
     */
    @Deprecated
    public PublicKey convertBytesToPublicKey(byte[] keyBytes) throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException {
        return convertBytesToPublicKey(EcCurve.P256, keyBytes);
    }
    
    /**
     * Converts byte array to an EC public key, by decoding the Q point (W in Java Security).
     * parameter.
     *
     * @param curve EC curve.
     * @param keyBytes Bytes to be converted to EC public key.
     * @return An instance of the EC public key on success, or null on failure.
     * @throws InvalidKeySpecException When provided bytes are not a correct key
     *                                 representation.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     * @throws GenericCryptoException When public key is invalid.
     */
    public PublicKey convertBytesToPublicKey(EcCurve curve, byte[] keyBytes) throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException {
        try {
            // Decode EC point using Bouncy Castle and extract its coordinates
            final ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curve.getName());
            if (ecSpec == null) { // can happen with incorrectly initialized crypto provider.
                throw new CryptoProviderException("Crypto provider does not support EC curve " + curve.getName());
            }
            final ECPoint point = ecSpec.getCurve().decodePoint(keyBytes).normalize();
            publicKeyValidator.validate(ecSpec.getCurve(), point);
            final ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
            return KeyFactory.getInstance("EC", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME).generatePublic(pubSpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        } catch (IllegalArgumentException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Converts provided byte array representing X coordinate of an EC public key.
     * @deprecated use {@link #convertPointBytesToPublicKey(EcCurve, byte[], byte[])}
     *
     * @param xBytes X coordinate.
     * @param yBytes Y coordinate.
     * @return Public key with provided coordinates.
     * @throws InvalidKeySpecException When provided bytes are not a correct key representation.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     * @throws GenericCryptoException  When public key is invalid.
     */
    @Deprecated
    public PublicKey convertPointBytesToPublicKey(byte[] xBytes, byte[] yBytes) throws GenericCryptoException, InvalidKeySpecException, CryptoProviderException {
        return convertPointBytesToPublicKey(EcCurve.P256, xBytes, yBytes);
    }

    /**
     * Converts provided byte array representing X coordinate of an EC public key.
     *
     * @param curve EC curve.
     * @param xBytes X coordinate.
     * @param yBytes Y coordinate.
     * @return Public key with provided coordinates.
     * @throws InvalidKeySpecException When provided bytes are not a correct key representation.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     * @throws GenericCryptoException  When public key is invalid.
     */
    public PublicKey convertPointBytesToPublicKey(EcCurve curve, byte[] xBytes, byte[] yBytes) throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException {
        try {
            // Make sure the values are interpreted as positive integer.
            final BigInteger x = new BigInteger(1, xBytes);
            final BigInteger y = new BigInteger(1, yBytes);

            // Validate the point is correct
            final ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curve.getName());
            if (ecSpec == null) { // can happen with incorrectly initialized crypto provider.
                throw new CryptoProviderException("Crypto provider does not support EC curve " + curve.getName());
            }
            final ECPoint point = ecSpec.getCurve().createPoint(x, y).normalize();
            publicKeyValidator.validate(ecSpec.getCurve(), point);
            final ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
            return KeyFactory.getInstance("EC", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME).generatePublic(pubSpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
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
     * @throws GenericCryptoException When private key is invalid.
     */
    public byte[] convertPrivateKeyToBytes(PrivateKey privateKey) throws GenericCryptoException {
        if (!(privateKey instanceof ECPrivateKey ecPrivateKey)) {
            throw new GenericCryptoException("Private key to be converted is not an instance of ECPrivateKey");
        }

        // Private key is stored including the sign bit as regular Java BigInteger representation
        return ecPrivateKey.getS().toByteArray();
    }

    /**
     * Convert a byte array to an EC private key by decoding the D number parameter (S in Java Security).
     * @deprecated use {@link #convertBytesToPrivateKey(EcCurve, byte[])}
     *
     * @param keyBytes Bytes to be converted to the EC private key.
     * @return An instance of EC private key decoded from the input bytes.
     * @throws InvalidKeySpecException The provided key bytes are not a valid EC
     *                                 private key.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     */
    @Deprecated
    public PrivateKey convertBytesToPrivateKey(byte[] keyBytes) throws InvalidKeySpecException, CryptoProviderException {
        return convertBytesToPrivateKey(EcCurve.P256, keyBytes);
    }

    /**
     * Convert a byte array to an EC private key by decoding the D number parameter (S in Java Security).
     *
     * @param curve EC curve.
     * @param keyBytes Bytes to be converted to the EC private key.
     * @return An instance of EC private key decoded from the input bytes.
     * @throws InvalidKeySpecException The provided key bytes are not a valid EC
     *                                 private key.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     */
    public PrivateKey convertBytesToPrivateKey(EcCurve curve, byte[] keyBytes) throws InvalidKeySpecException, CryptoProviderException {
        try {
            final ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curve.getName());
            final ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(new BigInteger(keyBytes), ecSpec);
            return KeyFactory.getInstance("EC", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME).generatePrivate(ecPrivateKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
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
        return new SecretKeySpec(bytesSecretKey, "RAW");
    }

}
