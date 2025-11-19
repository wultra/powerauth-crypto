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

package com.wultra.security.powerauth.crypto.lib.v4.dh;

import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.api.Kem;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for DHKEM key encapsulation mechanism.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class DhKemTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * DHKEM success test.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    @Test
    public void testDhKem_Success() throws GenericCryptoException {
        final Kem kem = new DhKem();
        final KeyPair keyPair = kem.generateKeyPair();
        final SecretKeyWithEncapsulation secret = kem.encapsulate(keyPair.getPublic());
        final SecretKey sharedKey = kem.decapsulate(keyPair.getPrivate(), secret.getEncapsulation());
        assertNotNull(sharedKey);
        assertEquals(48, sharedKey.getEncoded().length);
        assertArrayEquals(secret.getEncoded(), sharedKey.getEncoded());
    }

    /**
     * DHKEM invalid private key test.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    @Test
    public void testDhKem_InvalidPrivateKey() throws GenericCryptoException {
        final Kem kem = new DhKem();
        final KeyPair keyPair = kem.generateKeyPair();
        final SecretKeyWithEncapsulation secret = kem.encapsulate(keyPair.getPublic());
        final KeyPair keyPair2 = kem.generateKeyPair();
        final SecretKey sharedKey = kem.decapsulate(keyPair.getPrivate(), secret.getEncapsulation());
        final SecretKey sharedKey2 = kem.decapsulate(keyPair2.getPrivate(), secret.getEncapsulation());
        assertFalse(Arrays.equals(sharedKey.getEncoded(), sharedKey2.getEncoded()));
    }

}