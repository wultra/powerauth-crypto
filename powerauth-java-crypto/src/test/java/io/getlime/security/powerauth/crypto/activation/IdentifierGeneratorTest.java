/*
 * PowerAuth Crypto Library
 * Copyright 2019 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.activation;

import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.RecoveryInfo;
import io.getlime.security.powerauth.crypto.lib.model.RecoverySeed;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link IdentifierGenerator}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class IdentifierGeneratorTest {

    private final IdentifierGenerator identifierGenerator = new IdentifierGenerator();

    /**
     * Add crypto providers.
     */
    @BeforeAll
    public static void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testRecoveryCodeDerivation() throws Exception {
        // Number of PUKs to test
        int pukCount = 100;

        // Generate random secret key using ECDH
        KeyGenerator keyGenerator = new KeyGenerator();
        KeyPair keyPair1 = keyGenerator.generateKeyPair();
        PrivateKey privateKey1 = keyPair1.getPrivate();
        KeyPair keyPair2 = keyGenerator.generateKeyPair();
        PublicKey publicKey2 = keyPair2.getPublic();
        SecretKey secretKey = keyGenerator.computeSharedKey(privateKey1, publicKey2, true);

        // Generate recovery code and PUKs using secret key with seed information
        RecoveryInfo recoveryInfo = identifierGenerator.generateRecoveryCode(secretKey, pukCount, true);
        assertNotNull(recoveryInfo.getRecoveryCode());
        assertTrue(identifierGenerator.validateActivationCode(recoveryInfo.getRecoveryCode()));
        assertNotNull(recoveryInfo.getPuks());
        assertEquals(pukCount, recoveryInfo.getPuks().size());

        // Verify recovery seed
        RecoverySeed recoverySeed = recoveryInfo.getSeed();
        assertNotNull(recoverySeed.getNonce());
        assertNotNull(recoverySeed.getPukDerivationIndexes());
        assertEquals(pukCount, recoverySeed.getPukDerivationIndexes().size());
        assertEquals(recoveryInfo.getPuks().keySet(), recoverySeed.getPukDerivationIndexes().keySet());

        // Verify that PUK derivation indexes are unique
        assertEquals(pukCount, new HashSet<>(recoverySeed.getPukDerivationIndexes().values()).size());

        // Derive recovery code and PUKs using seed
        RecoveryInfo derivedRecoveryInfo = identifierGenerator.deriveRecoveryCode(secretKey, recoverySeed);

        // Verify that derive recovery code and PUKs match generated values
        assertEquals(recoveryInfo.getRecoveryCode(), derivedRecoveryInfo.getRecoveryCode());
        for (int i = 1; i <= pukCount; i++) {
            assertEquals(recoveryInfo.getPuks().get(i), derivedRecoveryInfo.getPuks().get(i));
        }
    }

    @Test
    void testGenerateActivationCode() throws Exception {
        final String result = identifierGenerator.generateActivationCode(new byte[10]);

        // Base32 is AAAAAAAAAAAAAAAAAAAA====
        assertEquals("AAAAA-AAAAA-AAAAA-AAAAA", result);
    }

}
