/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.app.cmd.util;

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;

/**
 * Utility class implementing processes related to data storage on client side.
 *
 * @author Petr Dvorak
 *
 */
public class EncryptedStorageUtil {

    /**
     * Encrypt the KEY_SIGNATURE_KNOWLEDGE key using a provided password.
     * @param password Password to be used for encryption.
     * @param signatureKnoweldgeSecretKey Original KEY_SIGNATURE_KNOWLEDGE key.
     * @param salt Random salt.
     * @param keyGenerator Key generator instance.
     * @return Encrypted KEY_SIGNATURE_KNOWLEDGE using password and random salt.
     * @throws InvalidKeyException In case invalid key is provided.
     * @throws IllegalBlockSizeException In case invalid key is provided.
     * @throws BadPaddingException In case invalid padding is provided.
     */
    public static byte[] storeSignatureKnowledgeKey(char[] password, SecretKey signatureKnoweldgeSecretKey, byte[] salt, KeyGenerator keyGenerator) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // Ask for the password and generate storage key
        SecretKey encryptionSignatureKnowledgeKey = keyGenerator.deriveSecretKeyFromPassword(new String(password), salt);

        // Encrypt the knowledge related key using the password derived key
        AESEncryptionUtils aes = new AESEncryptionUtils();
        byte[] signatureKnoweldgeSecretKeyBytes = PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertSharedSecretKeyToBytes(signatureKnoweldgeSecretKey);
        byte[] iv = new byte[16];
        byte[] cSignatureKnoweldgeSecretKey = aes.encrypt(signatureKnoweldgeSecretKeyBytes, iv, encryptionSignatureKnowledgeKey, "AES/CBC/NoPadding");
        return cSignatureKnoweldgeSecretKey;
    }

    /**
     * Decrypt the KEY_SIGNATURE_KNOWLEDGE key using a provided password.
     * @param password Password to be used for decryption.
     * @param cSignatureKnoweldgeSecretKeyBytes Encrypted KEY_SIGNATURE_KNOWLEDGE key.
     * @param salt Salt that was used for encryption.
     * @param keyGenerator Key generator instance.
     * @return Original KEY_SIGNATURE_KNOWLEDGE key.
     * @throws InvalidKeyException In case invalid key is provided
     * @throws IllegalBlockSizeException In case invalid key is provided
     * @throws BadPaddingException In case invalid padding is provided
     */
    public static SecretKey getSignatureKnowledgeKey(char[] password, byte[] cSignatureKnoweldgeSecretKeyBytes, byte[] salt, KeyGenerator keyGenerator) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // Ask for the password and generate storage key
        SecretKey encryptionSignatureKnowledgeKey = keyGenerator.deriveSecretKeyFromPassword(new String(password), salt);

        // Encrypt the knowledge related key using the password derived key
        AESEncryptionUtils aes = new AESEncryptionUtils();
        byte[] iv = new byte[16];
        byte[] signatureKnoweldgeSecretKeyBytes = aes.decrypt(cSignatureKnoweldgeSecretKeyBytes, iv, encryptionSignatureKnowledgeKey, "AES/CBC/NoPadding");
        return PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertBytesToSharedSecretKey(signatureKnoweldgeSecretKeyBytes);
    }

}
