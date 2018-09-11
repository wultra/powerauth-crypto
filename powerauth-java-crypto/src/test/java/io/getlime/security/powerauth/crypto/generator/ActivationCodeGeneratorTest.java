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

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.util.CRC16;
import org.junit.Test;

import java.nio.ByteBuffer;

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
        assertEquals(9031,  extractValueAndComputeCRC16("M3RL2-KSWPJ-2RGGY-QENDQ"));
        assertEquals(3737,  extractValueAndComputeCRC16("XYA3R-5NXJF-SEB42-RB2MQ"));
        assertEquals(45916, extractValueAndComputeCRC16("XW72M-U7YW4-X7K2L-GWNOA"));
        assertEquals(28079, extractValueAndComputeCRC16("CFGVO-PQVB5-HZIE5-ENWXQ"));
        assertEquals(49863, extractValueAndComputeCRC16("MQ2DV-3ES7H-V6CY7-CYLDQ"));
        assertEquals(33329, extractValueAndComputeCRC16("ND2R7-QDUDV-3OWDA-6QIYQ"));
        assertEquals(12686, extractValueAndComputeCRC16("MSG7J-Q6XMR-SEAT7-PGGHA"));
        assertEquals(8184,  extractValueAndComputeCRC16("D452K-G3LVX-33EXI-SD74A"));
        assertEquals(17241, extractValueAndComputeCRC16("HEMJK-E72T3-AFUYI-PINMQ"));
        assertEquals(38190, extractValueAndComputeCRC16("J4B5I-4HK6C-I6OVW-SSUXA"));
    }

    /**
     * Extract CRC-16 value from activation codes.
     * @param activationCode Activation code.
     * @return Extracted CRC-16 value.
     */
    private long extractValueAndComputeCRC16(String activationCode) {
        // Decode the Base32 value
        byte[] activationCodeBytes = BaseEncoding.base32().decode(activationCode.replace("-", ""));
        // Extract raw activation code value
        ByteBuffer byteBuffer = ByteBuffer.wrap(activationCodeBytes, 0, 10);
        byte[] activationCodeRaw = new byte[10];
        byteBuffer.get(activationCodeRaw, 0, 10);
        CRC16 crc16 = new CRC16();
        crc16.update(activationCodeRaw, 0, activationCodeRaw.length);
        return crc16.getValue();
    }

}
