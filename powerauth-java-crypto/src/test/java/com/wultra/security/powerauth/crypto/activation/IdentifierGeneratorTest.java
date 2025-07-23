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
package com.wultra.security.powerauth.crypto.activation;

import com.wultra.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
    void testGenerateActivationCode() throws Exception {
        final String result = identifierGenerator.generateActivationCode(new byte[10]);

        // Base32 is AAAAAAAAAAAAAAAAAAAA====
        assertEquals("AAAAA-AAAAA-AAAAA-AAAAA", result);
    }

}
