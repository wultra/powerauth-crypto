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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;

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

}
