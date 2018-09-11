/*
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
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

/**
 * Test activation code generator.
 */
public class ActivationCodeGeneratorTest {

    private IdentifierGenerator identifierGenerator = new IdentifierGenerator();

    @Test
    public void testActivationCodeGenerator()  {
        final Set<String> generatedActivationCodes = new HashSet<>();
        final int testRounds = 1000000;
        for (int i = 0; i < testRounds; i++) {
            String activationCode = identifierGenerator.generateActivationCode();
            // Verify activation code structure
            assertTrue(activationCode.matches("[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}"));
            generatedActivationCodes.add(activationCode);
        }
        // Verify that generated activation codes are unique
        assertEquals(testRounds, generatedActivationCodes.size());
    }
}
