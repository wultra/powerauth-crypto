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

package com.wultra.security.powerauth.crypto.lib.v4.runtime;

import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyLabel;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test of runtime key protection.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class KeyProtectionTest {

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    /**
     * Set up BC provider.
     */
    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testWrapAndUnwrapSameKey() throws Exception {
        SecretKey activationSecret = randomSecretKey();
        SecretKey originalKey = randomSecretKey();
        KeyLabel label = KeyLabel.RP_KEK_DEVICE_PRIVATE;

        byte[] wrapped = KeyProtection.wrapKey(originalKey, activationSecret, label);
        assertNotNull(wrapped, "Wrapped key must not be null");

        SecretKey unwrapped = KeyProtection.unwrapKey(wrapped, activationSecret, label);

        assertArrayEquals(
                KEY_CONVERTOR.convertSharedSecretKeyToBytes(originalKey),
                KEY_CONVERTOR.convertSharedSecretKeyToBytes(unwrapped)
        );
    }

    @Test
    void testWrappedKeyIsDifferent() throws Exception {
        SecretKey activationSecret = randomSecretKey();
        SecretKey originalKey = randomSecretKey();
        KeyLabel label = KeyLabel.RP_KDK_APP_VAULT_2FA;

        byte[] wrapped = KeyProtection.wrapKey(originalKey, activationSecret, label);

        // The wrapped key should not equal the raw key bytes
        assertFalse(Arrays.equals(wrapped, KEY_CONVERTOR.convertSharedSecretKeyToBytes(originalKey)));
    }

    private static SecretKey randomSecretKey() throws CryptoProviderException {
        return KEY_GENERATOR.generateRandomSecretKey(256);
    }

}
