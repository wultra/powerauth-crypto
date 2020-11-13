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
package io.getlime.security.powerauth.crypto.lib.generator;

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * An implementation of a high-level key generator class. Keys are generated
 * using elliptic curves (EC) and unless explicitly stated otherwise, they
 * have 128b length.
 *
 * @author Petr Dvorak
 *
 */
public class KeyGenerator {

    private static final Logger logger = LoggerFactory.getLogger(KeyGenerator.class);

    private static final String SECURE_RANDOM_ALGORITHM_NAME = "DEFAULT";

    private final KeyConvertor keyConvertor = new KeyConvertor();

    // The SecureRandom is initialized lazily. This is done so that the Bouncy Castle provider can be safely registered
    // dynamically before requesting the SecureRandom instance. It also allows KeyGenerator field instances
    // to be created inline outside of constructors.
    private volatile SecureRandom random;

    /**
     * Generate a new ECDH key pair using P256r1 curve.
     *
     * @return A new key pair instance, or null in case of an error.
     * @throws CryptoProviderException In case key cryptography provider is incorrectly initialized.
     */
    public KeyPair generateKeyPair() throws CryptoProviderException {
        try {
            // we assume BouncyCastle provider
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        }
    }

    /**
     * Computes a pre-shared key for given private key and public key (ECDH).
     *
     * @param privateKey A private key.
     * @param publicKey A public key.
     * @param keep32b Flag that indicates if the key should be kept 32 byte long (in case value is true), or shortened
     *                to 16 byte key using byte-by-byte xor operation.
     * @return A new instance of the pre-shared key.
     * @throws InvalidKeyException One of the provided keys are not valid keys.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey computeSharedKey(PrivateKey privateKey, PublicKey publicKey, boolean keep32b) throws InvalidKeyException, CryptoProviderException {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
            final byte[] sharedSecret = keyAgreement.generateSecret();
            final byte[] resultSecret;
            if (keep32b) {
                resultSecret = sharedSecret;
            } else {
                resultSecret = this.convert32Bto16B(sharedSecret);
            }
            return keyConvertor.convertBytesToSharedSecretKey(resultSecret);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        }
    }

    /**
     * Computes a pre-shared key for given private key and public key (ECDH). This method calls
     * {@link KeyGenerator#computeSharedKey(PrivateKey, PublicKey, boolean)} with the 'keep32b' parameter set to false.
     * As a result, the key that is returned by this function has only 16B. The key is obtained using byte-by-byte xor
     * operation on the original 32B key (0th byte with 15th, 1st byte with 16th, etc.)
     *
     * @param privateKey A private key.
     * @param publicKey A public key.
     * @return A new instance of the pre-shared key.
     * @throws InvalidKeyException One of the provided keys are not valid keys.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey computeSharedKey(PrivateKey privateKey, PublicKey publicKey) throws InvalidKeyException, CryptoProviderException {
        return computeSharedKey(privateKey, publicKey, false);
    }

    /**
     * Convert 32B byte long array to 16B long array by applying xor between first half and second half values.
     * @param original Original byte array, 32B long.
     * @return Result byte array, 16B long.
     */
    public byte[] convert32Bto16B(byte[] original) throws IllegalArgumentException {
        if (original.length != 32) {
            throw new IllegalArgumentException("Invalid byte array size, expected: 32, provided: " + original.length);
        }
        byte[] resultSecret = new byte[16];
        for (int i = 0; i < 16; i++) {
            resultSecret[i] = (byte) (original[i] ^ original[i + 16]);
        }
        return resultSecret;
    }

    /**
     * Generate a new random byte array with given length.
     *
     * @param len Number of random bytes to be generated.
     * @return An array with len random bytes.
     * @throws CryptoProviderException In case key cryptography provider is incorrectly initialized.
     */
    public byte[] generateRandomBytes(int len) throws CryptoProviderException {
        if (random == null) {
            synchronized (KeyGenerator.class) {
                if (random == null) {
                    try {
                        // Lazy initialization of SecureRandom allows safe Bouncy Castle provider initialization as well
                        // as initialization of KeyGenerator instances in fields outside of constructors.
                        random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM_NAME, PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
                    } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                        throw new CryptoProviderException("The Bouncy Castle provider was not initialized correctly");
                    }
                }
            }
        }
        byte[] randomBytes = new byte[len];
        random.nextBytes(randomBytes);
        return randomBytes;
    }

    /**
     * Generate a new random symmetric key.
     *
     * @return A new instance of a symmetric key.
     * @throws CryptoProviderException In case key cryptography provider is incorrectly initialized.
     */
    public SecretKey generateRandomSecretKey() throws CryptoProviderException {
        return keyConvertor.convertBytesToSharedSecretKey(generateRandomBytes(16));
    }

    /**
     * Derive a new secret key KEY_SHARED from a master secret key KEY_MASTER
     * based on following KDF:
     * <pre>
     * BYTES = index, total 16 bytes
     * KEY_SHARED[BYTES] = AES(BYTES, KEY_MASTER)
     * </pre>
     * @param secret A master shared key.
     * @param index A byte array index of the key.
     * @return A new derived key from a master key with given index.
     * @throws InvalidKeyException In case secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey deriveSecretKey(SecretKey secret, byte[] index) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        AESEncryptionUtils aes = new AESEncryptionUtils();
        byte[] iv = new byte[16];
        byte[] encryptedBytes = aes.encrypt(index, iv, secret);
        return keyConvertor.convertBytesToSharedSecretKey(Arrays.copyOf(encryptedBytes, 16));
    }

    /**
     * Derive a new secret key KEY_SHARED from a master secret key KEY_MASTER
     * based on following KDF:
     * <pre>
     * BYTES = index, total 16 bytes
     * KEY_SHARED[BYTES] = 32B_TO_16B(HMAC-SHA256(KEY_MASTER, BYTES))
     * </pre>
     * Note that this function is deprecated and should not be used for a new functionality.
     *
     * @param secret A master shared key.
     * @param index A byte array index of the key.
     * @return A new derived key from a master key with given index.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    @Deprecated
    public SecretKey deriveSecretKeyHmacLegacy(SecretKey secret, byte[] index) throws GenericCryptoException, CryptoProviderException {
        byte[] secretKeyBytes = keyConvertor.convertSharedSecretKeyToBytes(secret);
        HMACHashUtilities hmac = new HMACHashUtilities();
        byte[] derivedKey32 = hmac.hash(index, secretKeyBytes);
        byte[] newKeyBytes = convert32Bto16B(derivedKey32);
        return keyConvertor.convertBytesToSharedSecretKey(newKeyBytes);
    }

    /**
     * Derive a new secret key KEY_SHARED from a master secret key KEY_MASTER
     * based on following KDF:
     * <pre>
     * BYTES = index, total 16 bytes
     * KEY_SHARED[BYTES] = 32B_TO_16B(HMAC-SHA256(BYTES, KEY_MASTER))
     * </pre>
     *
     * @param secret A master shared key.
     * @param index A byte array index of the key.
     * @return A new derived key from a master key with given index.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey deriveSecretKeyHmac(SecretKey secret, byte[] index) throws GenericCryptoException, CryptoProviderException {
        byte[] secretKeyBytes = keyConvertor.convertSharedSecretKeyToBytes(secret);
        HMACHashUtilities hmac = new HMACHashUtilities();
        byte[] derivedKey32 = hmac.hash(secretKeyBytes, index);
        byte[] newKeyBytes = convert32Bto16B(derivedKey32);
        return keyConvertor.convertBytesToSharedSecretKey(newKeyBytes);
    }

    /**
     * Derive a long AES suitable key from a password and salt. Uses PBKDF with
     * 10 000 iterations.
     *
     * @param password A password used for key derivation.
     * @param salt A salt used for key derivation.
     * @return A new secret key derived from the password.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey deriveSecretKeyFromPassword(String password, byte[] salt) throws CryptoProviderException {
        return deriveSecretKeyFromPassword(password, salt, PowerAuthConfiguration.PBKDF_ITERATIONS);
    }

    /**
     * Derive a long AES suitable key from a password and salt. Uses PBKDF with specified
     * number of iterations.
     *
     * @param password A password used for key derivation.
     * @param salt A salt used for key derivation.
     * @param iterations Number of iterations used in PBKDF.
     * @return A new secret key derived from the password.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey deriveSecretKeyFromPassword(String password, byte[] salt, int iterations) throws CryptoProviderException {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 128);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            byte[] keyBytes = skf.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        }
    }

}
