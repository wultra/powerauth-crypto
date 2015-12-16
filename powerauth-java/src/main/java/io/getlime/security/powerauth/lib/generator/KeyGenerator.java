/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.lib.generator;

import io.getlime.security.powerauth.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;
import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyGenerator {

    private final SecureRandom random = new SecureRandom();

    /**
     * Generate a new ECDH key pair using P256r1 curve.
     *
     * @return A new key pair instance, or null in case of an error.
     */
    public KeyPair generateKeyPair() {
        try {
            // we assume BouncyCastle provider
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", "BC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();
            return kp;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(this.getClass().getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Computes a pre-shared key for given private key and public key (ECDH).
     *
     * @param privateKey A private key.
     * @param publicKey A public key.
     * @return A new instance of the pre-shared key.
     * @throws InvalidKeyException One of the provided keys are not valid keys.
     */
    public SecretKey computeSharedKey(PrivateKey privateKey, PublicKey publicKey) throws InvalidKeyException {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
            // Generate 16B key from 32B key by applying XOR
            final byte[] sharedSecret = keyAgreement.generateSecret();
            byte[] resultSecret = new byte[16];
            for (int i = 0; i < 16; i++) {
                resultSecret[i] = (byte) (sharedSecret[i] ^ sharedSecret[i + 16]);
            }
            return new KeyConversionUtils().convertBytesToSharedSecretKey(resultSecret);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(this.getClass().getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Generate a new random byte array with given length.
     *
     * @param len Number of random bytes to be generated.
     * @return An array with len random bytes.
     */
    public byte[] generateRandomBytes(int len) {
        byte[] randomBytes = new byte[len];
        random.nextBytes(randomBytes);
        return randomBytes;
    }

    /**
     * Generate a new random symmetric key.
     *
     * @return A new instance of a symmetric key.
     */
    public SecretKey generateRandomSecretKey() {
        return new KeyConversionUtils().convertBytesToSharedSecretKey(generateRandomBytes(16));
    }

    /**
     * Derives a new secret key KEY_SHARED from a master secret key KEY_MASTER
     * based on following KDF:
     *
     * BYTES = index, padded from left with 0x00, total 16 bytes
     * KEY_SHARED[BYTES] = AES(BYTES, KEY_MASTER)
     *
     * @param secret A master shared key
     * @param index An index of the key
     * @return A new derived key from a master key with given index.
     */
    public SecretKey deriveSecretKey(SecretKey secret, long index) {
        try {
            AESEncryptionUtils aes = new AESEncryptionUtils();
            byte[] bytes = ByteBuffer.allocate(16).putLong(0L).putLong(index).array();
            byte[] iv = new byte[16];
            byte[] encryptedBytes = aes.encrypt(bytes, iv, secret);
            return new KeyConversionUtils().convertBytesToSharedSecretKey(Arrays.copyOf(encryptedBytes, 16));
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(KeyGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Derive a long AES suitable key from a password and salt. Uses PBKDF with
     * 10 000 iterations.
     *
     * @param password A password used for key derivation
     * @param salt A salt used for key derivation
     * @return A new secret key derived from the password.
     */
    public SecretKey deriveSecretKeyFromPassword(String password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PowerAuthConstants.PBKDF_ITERATIONS, 128);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] keyBytes = skf.generateSecret(spec).getEncoded();
            SecretKey encryptionKey = new SecretKeySpec(keyBytes, "AES/ECB/NoPadding");
            return encryptionKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(KeyGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

}
