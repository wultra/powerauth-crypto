/*
 * PowerAuth Crypto Library
 * Copyright 2025 Wultra s.r.o.
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

package io.getlime.security.powerauth.crypto.lib.v4;

import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for PQC digital signature algorithm.
 */
public class PqcDsaTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * PQC DSA success test.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    @Test
    public void testPqcDsa_Success() throws GenericCryptoException {
        final PqcDsa pqcDsa = new PqcDsa();
        final KeyPair keyPair = pqcDsa.generateKeyPair();
        final byte[] testMessage = "test_message".getBytes(StandardCharsets.UTF_8);
        byte[] signature = pqcDsa.sign(keyPair.getPrivate(), testMessage);
        assertTrue(pqcDsa.verify(keyPair.getPublic(), testMessage, signature));
    }

    /**
     * PQC DSA invalid signature test.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    @Test
    public void testPqcDsa_InvalidSignature() throws GenericCryptoException {
        final PqcDsa pqcDsa = new PqcDsa();
        final KeyPair keyPair = pqcDsa.generateKeyPair();
        final byte[] testMessage = "test_message".getBytes(StandardCharsets.UTF_8);
        assertFalse(pqcDsa.verify(keyPair.getPublic(), testMessage, "invalid".getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * PQC DSA invalid private key test.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    @Test
    public void testPqcDsa_InvalidPrivateKey() throws GenericCryptoException {
        final PqcDsa pqcDsa = new PqcDsa();
        final KeyPair keyPair = pqcDsa.generateKeyPair();
        final KeyPair keyPair2 = pqcDsa.generateKeyPair();
        final byte[] testMessage = "test_message".getBytes(StandardCharsets.UTF_8);
        byte[] signature = pqcDsa.sign(keyPair.getPrivate(), testMessage);
        assertFalse(pqcDsa.verify(keyPair2.getPublic(), testMessage, signature));
    }

    /**
     * PQC DSA null message test.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    @Test
    public void testPqcDsa_NullMessage() throws GenericCryptoException {
        final PqcDsa pqcDsa = new PqcDsa();
        final KeyPair keyPair = pqcDsa.generateKeyPair();
        assertThrows(NullPointerException.class, () -> pqcDsa.sign(keyPair.getPrivate(), null));
    }

    /**
     * PQC DSA empty message test.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    @Test
    public void testPqcDsa_EmptyMessage() throws GenericCryptoException {
        final PqcDsa pqcDsa = new PqcDsa();
        final KeyPair keyPair = pqcDsa.generateKeyPair();
        final byte[] emptyMessage = new byte[0];
        byte[] signature = pqcDsa.sign(keyPair.getPrivate(), emptyMessage);
        assertTrue(pqcDsa.verify(keyPair.getPublic(), emptyMessage, signature));
    }

}
