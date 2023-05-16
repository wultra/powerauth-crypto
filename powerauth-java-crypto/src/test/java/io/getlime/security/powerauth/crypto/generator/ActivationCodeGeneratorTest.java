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
package io.getlime.security.powerauth.crypto.generator;

import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test activation code generator.
 */
public class ActivationCodeGeneratorTest {

    private final IdentifierGenerator identifierGenerator = new IdentifierGenerator();

    /**
     * Set up crypto providers
     */
    @BeforeAll
    public static void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test generator of activation codes and validate CRC-16 checksum.
     */
    @Test
    public void testActivationCodeGenerator() throws CryptoProviderException {
        int testRounds = 10000;
        for (int i = 0; i < testRounds; i++) {
            String activationCode = identifierGenerator.generateActivationCode();
            assertTrue(identifierGenerator.validateActivationCode(activationCode));
        }
    }

}
