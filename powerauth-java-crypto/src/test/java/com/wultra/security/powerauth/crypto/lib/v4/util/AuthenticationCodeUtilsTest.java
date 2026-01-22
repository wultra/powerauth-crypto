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

package com.wultra.security.powerauth.crypto.lib.v4.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.AuthenticationCodeUtils;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for {@link AuthenticationCodeUtils}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class AuthenticationCodeUtilsTest {

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final AuthenticationCodeUtils AUTHENTICATION_CODE_UTILS = new AuthenticationCodeUtils();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static Stream<Map<String, String>> authCode_Provider() throws IOException {
        final InputStream stream = AuthenticationCodeUtilsTest.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v4/util/Auth_Code_Test_Vectors.json");
        final Map<String, List<Map<String, String>>> authCodes = MAPPER.readValue(stream, new TypeReference<>() {});
        return authCodes.get("auth_code_test_vectors").stream();
    }

    @ParameterizedTest
    @MethodSource("authCode_Provider")
    void testAuthCodes(Map<String, String> vector) throws GenericCryptoException {
        final SecretKey key1 = KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(vector.get("key1")));
        final SecretKey key2 = KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(vector.get("key2")));
        final SecretKey key3 = KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(vector.get("key3")));
        final byte[] ctrData = Base64.getDecoder().decode(vector.get("ctrData"));
        final byte[] inputData = Base64.getDecoder().decode(vector.get("inputData"));
        final String authCodeOnlineExpected = vector.get("authCodeOnline");
        final String authCodeOfflineExpected = vector.get("authCodeOffline");
        assertEquals(authCodeOnlineExpected, AUTHENTICATION_CODE_UTILS.computeOnlineAuthCode(inputData, Arrays.asList(key1, key2, key3), ctrData));
        assertEquals(authCodeOfflineExpected, AUTHENTICATION_CODE_UTILS.computeOfflineAuthCode(inputData, Arrays.asList(key1, key2, key3), ctrData));
    }

    @Test
    void generateAuthCodeVectors() throws Exception {
        final int count = 100;
        final int keyLen = 32;
        final int ctrLen = 32;
        final byte[] inputData = "test_data".getBytes(StandardCharsets.UTF_8);
        final List<Map<String, String>> vectors = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            final byte[] key1b = KEY_GENERATOR.generateRandomBytes(keyLen);
            final byte[] key2b = KEY_GENERATOR.generateRandomBytes(keyLen);
            final byte[] key3b = KEY_GENERATOR.generateRandomBytes(keyLen);
            final byte[] ctr = KEY_GENERATOR.generateRandomBytes(ctrLen);
            final SecretKey key1 = KEY_CONVERTOR.convertBytesToSharedSecretKey(key1b);
            final SecretKey key2 = KEY_CONVERTOR.convertBytesToSharedSecretKey(key2b);
            final SecretKey key3 = KEY_CONVERTOR.convertBytesToSharedSecretKey(key3b);
            final List<SecretKey> keys = Arrays.asList(key1, key2, key3);
            final String online = AUTHENTICATION_CODE_UTILS.computeOnlineAuthCode(inputData, keys, ctr);
            final String offline = AUTHENTICATION_CODE_UTILS.computeOfflineAuthCode(inputData, keys, ctr);

            final Map<String, String> v = new LinkedHashMap<>();
            v.put("key1", Base64.getEncoder().encodeToString(key1b));
            v.put("key2", Base64.getEncoder().encodeToString(key2b));
            v.put("key3", Base64.getEncoder().encodeToString(key3b));
            v.put("ctrData", Base64.getEncoder().encodeToString(ctr));
            v.put("inputData", Base64.getEncoder().encodeToString(inputData));
            v.put("authCodeOnline", online);
            v.put("authCodeOffline", offline);

            vectors.add(v);
        }

        final Map<String, Object> root = new LinkedHashMap<>();
        root.put("auth_code_test_vectors", vectors);

        System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root));
    }

}
