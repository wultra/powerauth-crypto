package com.wultra.security.powerauth.crypto.lib.util;

import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Key convertor for conversion of asymmetric keys for PQC.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PqcDsaKeyConvertor {

    private static final Logger logger = LoggerFactory.getLogger(PqcDsaKeyConvertor.class);

    private final String algorithmName;

    /**
     * Constructs convertor for ML-DSA algorithm.
     */
    public PqcDsaKeyConvertor() {
        this("ML-DSA");
    }

    /**
     * Constructs convertor for a specific PQC DSA algorithm.
     * @param algorithmName Algorithm name (e.g., "ML-DSA")
     */
    public PqcDsaKeyConvertor(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Converts public key to byte array.
     *
     * @param publicKey An ML-DSA public key to be converted.
     * @return A byte array representation of the ML-DSA public key.
     * @throws GenericCryptoException In case conversion fails.
     */
    public byte[] convertPublicKeyToBytes(PublicKey publicKey) throws GenericCryptoException {
        if (publicKey == null) {
            throw new GenericCryptoException("Missing public key");
        }
        return publicKey.getEncoded();
    }

    /**
     * Converts byte array to an ML-DSA public key.
     *
     * @param keyBytes Bytes to be converted to ML-DSA public key.
     * @return An instance of the ML-DSA public key.
     * @throws GenericCryptoException Throw in case conversion fails.
     */
    public PublicKey convertBytesToPublicKey(byte[] keyBytes) throws GenericCryptoException {
        if (keyBytes == null) {
            throw new GenericCryptoException("Missing public key bytes");
        }
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(algorithmName, "BC");
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.debug(e.getMessage(), e);
            throw new GenericCryptoException("Key conversion failed", e);
        }
    }

    /**
     * Converts private key to byte array.
     *
     * @param privateKey An ML-DSA private key to be converted.
     * @return A byte array representation of the ML-DSA private key.
     * @throws GenericCryptoException In case conversion fails.
     */
    public byte[] convertPrivateKeyToBytes(PrivateKey privateKey) throws GenericCryptoException {
        if (privateKey == null) {
            throw new GenericCryptoException("Missing private key");
        }
        return privateKey.getEncoded();
    }

    /**
     * Convert a byte array to an ML-DSA private key.
     *
     * @param keyBytes Bytes to be converted to the ML-DSA private key.
     * @return An instance of ML-DSA private key decoded from the input bytes.
     * @throws GenericCryptoException Throw in case conversion fails.
     */
    public PrivateKey convertBytesToPrivateKey(byte[] keyBytes) throws GenericCryptoException {
        if (keyBytes == null) {
            throw new GenericCryptoException("Missing public key bytes");
        }
        try {
            final KeyFactory keyFactoryMlDsa = KeyFactory.getInstance(algorithmName, "BC");
            final PKCS8EncodedKeySpec keySpecMlDsa = new PKCS8EncodedKeySpec(keyBytes);
            return keyFactoryMlDsa.generatePrivate(keySpecMlDsa);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.debug(e.getMessage(), e);
            throw new GenericCryptoException("Key conversion failed", e);
        }
    }
}
