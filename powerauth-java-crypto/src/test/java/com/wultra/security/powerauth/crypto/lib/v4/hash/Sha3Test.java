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
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Test for SHA-3 primitives.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class Sha3Test {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static Stream<Map<String, String>> jsonDataSha3_256Provider() throws IOException {
        InputStream sha3_256Stream = Sha3Test.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v4/hash/SHA3_256_Test_Vectors.json");
        Map<String, List<Map<String, String>>> sha3_256Data = MAPPER.readValue(sha3_256Stream, new TypeReference<>() {});
        return sha3_256Data.get("sha3_256_test_vectors").stream();
    }

    static Stream<Map<String, String>> jsonDataSha3_384Provider() throws IOException {
        InputStream sha3_384Stream = Sha3Test.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v4/hash/SHA3_384_Test_Vectors.json");
        Map<String, List<Map<String, String>>> sha3_384Data = MAPPER.readValue(sha3_384Stream, new TypeReference<>() {});
        return sha3_384Data.get("sha3_384_test_vectors").stream();
    }

    @ParameterizedTest
    @MethodSource("jsonDataSha3_256Provider")
    void testSha3_256(Map<String, String> vector) {
        String msgHex = vector.get("msg");
        String expectedMdHex = vector.get("digest");
        byte[] msgBytes = Hex.decode(msgHex);
        byte[] expectedMdBytes = Hex.decode(expectedMdHex);
        byte[] computedMdBytes = Sha3.hash256(msgBytes);
        assertArrayEquals(expectedMdBytes, computedMdBytes, "SHA3-256 failed for Msg: " + msgHex);
    }

    @ParameterizedTest
    @MethodSource("jsonDataSha3_384Provider")
    void testSha3_384(Map<String, String> vector) {
        String msgHex = vector.get("msg");
        String expectedMdHex = vector.get("digest");
        byte[] msgBytes = Hex.decode(msgHex);
        byte[] expectedMdBytes = Hex.decode(expectedMdHex);
        byte[] computedMdBytes = Sha3.hash384(msgBytes);
        assertArrayEquals(expectedMdBytes, computedMdBytes, "SHA3-384 failed for Msg: " + msgHex);
    }

}