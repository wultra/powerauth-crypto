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

package com.wultra.security.powerauth.crypto.lib.v4.hash;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Tests for hash-based counter.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class HashBasedCounterTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static Stream<Map<String, String>> jsonDataHashBasedCounterProvider() throws IOException {
        InputStream sha3_256Stream = HashBasedCounterTest.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v4/hash/Hash_Based_Counter_Test_Vectors.json");
        Map<String, List<Map<String, String>>> sha3_256Data = MAPPER.readValue(sha3_256Stream, new TypeReference<>() {});
        return sha3_256Data.get("hash_based_counter_test_vectors").stream();
    }

    @ParameterizedTest
    @MethodSource("jsonDataHashBasedCounterProvider")
    void testHashBasedCounter(Map<String, String> vector) throws GenericCryptoException {
        final HashBasedCounter counter = new HashBasedCounter("4.0");
        byte[] ctrData = Base64.getDecoder().decode(vector.get("ctrData[0]"));
        for (int i = 0; i < 20; i++) {
            final byte[] ctrDataNext = Base64.getDecoder().decode(vector.get("ctrData[" + (i + 1) + "]"));
            ctrData = counter.next(ctrData);
            assertArrayEquals(ctrDataNext, ctrData);
        }
    }

}