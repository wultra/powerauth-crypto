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

package io.getlime.security.powerauth.crypto.lib.v4;

import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for PQC key encapsulation mechanism.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class PqcKemTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * PQC KEM success test.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    @Test
    public void testPqcKem_Success() throws GenericCryptoException {
        final PqcKem kem = new PqcKem();
        final KeyPair keyPair = kem.generateKeyPair();
        final SecretKeyWithEncapsulation secret = kem.encapsulate(keyPair.getPublic());
        final SecretKey sharedKey = kem.decapsulate(keyPair.getPrivate(), secret.getEncapsulation());
        assertNotNull(sharedKey);
        assertEquals(32, sharedKey.getEncoded().length);
        assertArrayEquals(secret.getEncoded(), sharedKey.getEncoded());
    }

    /**
     * PQC KEM success test.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    @Test
    public void testPqcKem_InvalidPrivateKey() throws GenericCryptoException {
        final PqcKem kem = new PqcKem();
        final KeyPair keyPair = kem.generateKeyPair();
        final SecretKeyWithEncapsulation secret = kem.encapsulate(keyPair.getPublic());
        final KeyPair keyPair2 = kem.generateKeyPair();
        final SecretKey sharedKey = kem.decapsulate(keyPair.getPrivate(), secret.getEncapsulation());
        final SecretKey sharedKey2 = kem.decapsulate(keyPair2.getPrivate(), secret.getEncapsulation());
        assertFalse(Arrays.equals(sharedKey.getEncoded(), sharedKey2.getEncoded()));
    }

}