/*
 * PowerAuth Crypto Library
 * Copyright 2024 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.lib.v4;

import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for AEAD encryption and decryption.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class AeadTest {

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private SecretKey key;
    private byte[] plaintext;
    private byte[] keyContext;
    private byte[] associatedData;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    void setUp() throws Exception {
        key = KEY_GENERATOR.generateRandomSecretKey(32);
        plaintext = KEY_GENERATOR.generateRandomBytes(128);
        keyContext =  KEY_GENERATOR.generateRandomBytes(16);
        associatedData = KEY_GENERATOR.generateRandomBytes(16);
    }

    @Test
    void testAeadSuccess() throws Exception {
        byte[] nonce = new KeyGenerator().generateRandomBytes(12);
        byte[] ciphertext = Aead.seal(key, keyContext, nonce, associatedData, plaintext);
        assertNotNull(ciphertext);
        byte[] decrypted = Aead.open(key, keyContext, associatedData, ciphertext);
        assertArrayEquals(plaintext, decrypted);
    }

   @Test
    void testAeadSuccessGeneratedNonce() throws Exception {
        byte[] ciphertext = Aead.seal(key, keyContext, null, associatedData, plaintext);
        assertNotNull(ciphertext);
        byte[] decrypted = Aead.open(key, keyContext, associatedData, ciphertext);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void testInvalidMac() throws Exception {
        byte[] nonce = new KeyGenerator().generateRandomBytes(12);
        byte[] ciphertext = Aead.seal(key, keyContext, nonce, associatedData, plaintext);
        ciphertext[0] += 1;
        assertThrows(GenericCryptoException.class, () -> Aead.open(key, keyContext, associatedData, ciphertext));
    }

    @Test
    void testInvalidNonceLength() {
        byte[] invalidNonce = new byte[11];
        assertThrows(GenericCryptoException.class, () -> Aead.seal(key, keyContext, invalidNonce, associatedData, plaintext), "Invalid nonce length should throw exception");
    }

    @Test
    void testExtractNonce() throws Exception {
        byte[] nonce = new KeyGenerator().generateRandomBytes(12);
        byte[] ciphertext = Aead.seal(key, keyContext, nonce, associatedData, plaintext);
        byte[] extractedNonce = Aead.extractNonce(ciphertext);
        assertArrayEquals(nonce, extractedNonce);
    }

    @Test
    void testInvalidKey() throws Exception {
        SecretKey wrongKey = KEY_GENERATOR.generateRandomSecretKey(32);
        byte[] ciphertext = Aead.seal(key, keyContext, null, associatedData, plaintext);
        assertThrows(GenericCryptoException.class, () -> Aead.open(wrongKey, keyContext, associatedData, ciphertext), "Decryption with an invalid key should throw exception");
    }

    @Test
    void testNullAssociatedData() throws Exception {
        byte[] ciphertext = Aead.seal(key, keyContext, null, null, plaintext);
        byte[] decrypted = Aead.open(key, keyContext, null, ciphertext);
        assertArrayEquals(plaintext, decrypted);
    }

}