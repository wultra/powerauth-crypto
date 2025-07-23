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
package com.wultra.security.powerauth.crypto.lib.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretEcdheTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test of token utility methods.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class TokenUtilsTest {

    private static final TokenUtils TOKEN_UTILS = new TokenUtils();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testTokenDigestV30() throws CryptoProviderException, GenericCryptoException {
        final byte[] tokenSecret = TOKEN_UTILS.generateTokenSecret(16);
        final byte[] timestamp = TOKEN_UTILS.generateTokenTimestamp();
        final byte[] nonce = TOKEN_UTILS.generateTokenNonce();
        final byte[] tokenDigest = TOKEN_UTILS.computeTokenDigest(nonce, timestamp, "3.0", tokenSecret);
        assertTrue(TOKEN_UTILS.validateTokenDigest(nonce, timestamp, "3.0", tokenSecret, tokenDigest));
    }

    @Test
    public void testTokenDigestV31() throws CryptoProviderException, GenericCryptoException {
        final byte[] tokenSecret = TOKEN_UTILS.generateTokenSecret(16);
        final byte[] timestamp = TOKEN_UTILS.generateTokenTimestamp();
        final byte[] nonce = TOKEN_UTILS.generateTokenNonce();
        final byte[] tokenDigest = TOKEN_UTILS.computeTokenDigest(nonce, timestamp, "3.1", tokenSecret);
        assertTrue(TOKEN_UTILS.validateTokenDigest(nonce, timestamp, "3.1", tokenSecret, tokenDigest));
    }

    @Test
    public void testTokenDigestV32() throws CryptoProviderException, GenericCryptoException {
        final byte[] tokenSecret = TOKEN_UTILS.generateTokenSecret(16);
        final byte[] timestamp = TOKEN_UTILS.generateTokenTimestamp();
        final byte[] nonce = TOKEN_UTILS.generateTokenNonce();
        final byte[] tokenDigest = TOKEN_UTILS.computeTokenDigest(nonce, timestamp, "3.2", tokenSecret);
        assertTrue(TOKEN_UTILS.validateTokenDigest(nonce, timestamp, "3.2", tokenSecret, tokenDigest));
    }

    @Test
    public void testTokenDigestV33() throws CryptoProviderException, GenericCryptoException {
        final byte[] tokenSecret = TOKEN_UTILS.generateTokenSecret(16);
        final byte[] timestamp = TOKEN_UTILS.generateTokenTimestamp();
        final byte[] nonce = TOKEN_UTILS.generateTokenNonce();
        final byte[] tokenDigest = TOKEN_UTILS.computeTokenDigest(nonce, timestamp, "3.3", tokenSecret);
        assertTrue(TOKEN_UTILS.validateTokenDigest(nonce, timestamp, "3.3", tokenSecret, tokenDigest));
    }

    @Test
    public void testTokenDigestV40() throws CryptoProviderException, GenericCryptoException {
        final byte[] tokenSecret = TOKEN_UTILS.generateTokenSecret(32);
        final byte[] timestamp = TOKEN_UTILS.generateTokenTimestamp();
        final byte[] nonce = TOKEN_UTILS.generateTokenNonce();
        final byte[] tokenDigest = TOKEN_UTILS.computeTokenDigest(nonce, timestamp, "4.0", tokenSecret);
        assertTrue(TOKEN_UTILS.validateTokenDigest(nonce, timestamp, "4.0", tokenSecret, tokenDigest));
    }

    private static Stream<Map<String, String>> jsonDataTokenDigestV40_Provider() throws IOException {
        final InputStream stream = SharedSecretEcdheTest.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v4/token/Token_Digest_Test_Vectors.json");
        final Map<String, List<Map<String, String>>> testData = MAPPER.readValue(stream, new TypeReference<>() {});
        return testData.get("token_digest_test_vectors").stream();
    }

    @ParameterizedTest
    @MethodSource("jsonDataTokenDigestV40_Provider")
    public void testVectorsTokenDigestV40(Map<String, String> vector) throws Exception {
        final byte[] tokenSecret = Base64.getDecoder().decode(vector.get("tokenSecret"));
        final byte[] nonce = Base64.getDecoder().decode(vector.get("nonce"));
        final byte[] timestamp = Base64.getDecoder().decode(vector.get("timestamp"));
        final byte[] tokenDigest = Base64.getDecoder().decode(vector.get("tokenDigest"));
        assertTrue(TOKEN_UTILS.validateTokenDigest(nonce, timestamp, "4.0", tokenSecret, tokenDigest));
    }

}
