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

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

/**
 * Test activation code generator.
 */
public class ActivationCodeGeneratorTest {

    private IdentifierGenerator identifierGenerator = new IdentifierGenerator();

    /**
     * Test generator of activation codes and validate CRC-16 checksum.
     */
    @Test
    public void testActivationCodeGenerator()  {
        int testRounds = 10000;
        for (int i = 0; i < testRounds; i++) {
            String activationCode = identifierGenerator.generateActivationCode();
            assertTrue(identifierGenerator.validateActivationCode(activationCode));
        }
    }

    /**
     * Test known CRC-16 vectors for activations.
     */
    @Test
    public void testCRC16ForActivations() {
        assertEquals(9031,  identifierGenerator.computeChecksum("M3RL2-KSWPJ-2RGGY-QENDQ"));
        assertEquals(3737,  identifierGenerator.computeChecksum("XYA3R-5NXJF-SEB42-RB2MQ"));
        assertEquals(45916, identifierGenerator.computeChecksum("XW72M-U7YW4-X7K2L-GWNOA"));
        assertEquals(28079, identifierGenerator.computeChecksum("CFGVO-PQVB5-HZIE5-ENWXQ"));
        assertEquals(49863, identifierGenerator.computeChecksum("MQ2DV-3ES7H-V6CY7-CYLDQ"));
        assertEquals(33329, identifierGenerator.computeChecksum("ND2R7-QDUDV-3OWDA-6QIYQ"));
        assertEquals(12686, identifierGenerator.computeChecksum("MSG7J-Q6XMR-SEAT7-PGGHA"));
        assertEquals(8184,  identifierGenerator.computeChecksum("D452K-G3LVX-33EXI-SD74A"));
        assertEquals(17241, identifierGenerator.computeChecksum("HEMJK-E72T3-AFUYI-PINMQ"));
        assertEquals(38190, identifierGenerator.computeChecksum("J4B5I-4HK6C-I6OVW-SSUXA"));
    }


}
