package io.getlime.security.powerauth.crypto.lib.v4.hash;

import com.fasterxml.jackson.core.type.TypeReference;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class Sha3Test {

    private static List<Map<String, String>> sha3_256TestVectors;
    private static List<Map<String, String>> sha3_384TestVectors;

    @BeforeAll
    static void loadTestVectors() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        InputStream sha3_256Stream = Sha3Test.class.getResourceAsStream("/io/getlime/security/powerauth/crypto/lib/v4/hash/SHA3_256_TestVectors.json");
        InputStream sha3_384Stream = Sha3Test.class.getResourceAsStream("/io/getlime/security/powerauth/crypto/lib/v4/hash/SHA3_384_TestVectors.json");
        Map<String, List<Map<String, String>>> sha3_256Data = mapper.readValue(sha3_256Stream, new TypeReference<>() {});
        Map<String, List<Map<String, String>>> sha3_384Data = mapper.readValue(sha3_384Stream, new TypeReference<>() {});
        sha3_256TestVectors = sha3_256Data.get("sha3_256_test_vectors");
        sha3_384TestVectors = sha3_384Data.get("sha3_384_test_vectors");
    }

    @Test
    void testSha3_256() {
        for (Map<String, String> vector : sha3_256TestVectors) {
            String msgHex = vector.get("msg");
            String expectedMdHex = vector.get("digest");
            byte[] msgBytes = Hex.decode(msgHex);
            byte[] expectedMdBytes = Hex.decode(expectedMdHex);
            byte[] computedMdBytes = Sha3.hash256(msgBytes);
            assertArrayEquals(expectedMdBytes, computedMdBytes, "SHA3-256 failed for Msg: " + msgHex);
        }
    }

    @Test
    void testSha3_384() {
        for (Map<String, String> vector : sha3_384TestVectors) {
            String msgHex = vector.get("msg");
            String expectedMdHex = vector.get("digest");
            byte[] msgBytes = Hex.decode(msgHex);
            byte[] expectedMdBytes = Hex.decode(expectedMdHex);
            byte[] computedMdBytes = Sha3.hash384(msgBytes);
            assertArrayEquals(expectedMdBytes, computedMdBytes, "SHA3-384 failed for Msg: " + msgHex);
        }
    }

}
