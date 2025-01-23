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

package io.getlime.security.powerauth.crypto.lib.v4.kdf;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Tests for KDF based on KMAC256 using NIST test vectors.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class KdfTest {

    @Test
    void testKmac256Vector4() throws Exception {
        // Test Vector 4 (https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/kmac_samples.pdf)
        byte[] key = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
        byte[] data = Hex.decode("00010203");
        byte[] customString = "My Tagged Application".getBytes(StandardCharsets.UTF_8);
        int outputLength = 64;
        byte[] expectedOutput = Hex.decode("20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD");
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        byte[] output = Kmac.kmac256(secretKey, data, outputLength, customString);
        assertArrayEquals(expectedOutput, output, "KMAC256 output does not match expected output.");
    }

    @Test
    void testKmac256Vector5() throws Exception {
        // Test Vector 5 (https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/kmac_samples.pdf)
        byte[] key = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
        byte[] data = Hex.decode("000102030405060708090A0B0C0D0E0F" +
                "101112131415161718191A1B1C1D1E1F" +
                "202122232425262728292A2B2C2D2E2F" +
                "303132333435363738393A3B3C3D3E3F" +
                "404142434445464748494A4B4C4D4E4F" +
                "505152535455565758595A5B5C5D5E5F" +
                "606162636465666768696A6B6C6D6E6F" +
                "707172737475767778797A7B7C7D7E7F" +
                "808182838485868788898A8B8C8D8E8F" +
                "909192939495969798999A9B9C9D9E9F" +
                "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF" +
                "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" +
                "C0C1C2C3C4C5C6C7");
        byte[] customString = null;
        int outputLength = 64;
        byte[] expectedOutput = Hex.decode("75358CF39E41494E949707927CEE0AF2" +
                "0A3FF553904C86B08F21CC414BCFD691" +
                "589D27CF5E15369CBBFF8B9A4C2EB178" +
                "00855D0235FF635DA82533EC6B759B69");
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        byte[] output = Kmac.kmac256(secretKey, data, outputLength, customString);
        assertArrayEquals(expectedOutput, output, "KMAC256 output does not match expected output.");
    }

    @Test
    void testKmac256Vector6() throws Exception {
        // Test Vector 6 (https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/kmac_samples.pdf)
        byte[] key = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
        byte[] data = Hex.decode("000102030405060708090A0B0C0D0E0F" +
                "101112131415161718191A1B1C1D1E1F" +
                "202122232425262728292A2B2C2D2E2F" +
                "303132333435363738393A3B3C3D3E3F" +
                "404142434445464748494A4B4C4D4E4F" +
                "505152535455565758595A5B5C5D5E5F" +
                "606162636465666768696A6B6C6D6E6F" +
                "707172737475767778797A7B7C7D7E7F" +
                "808182838485868788898A8B8C8D8E8F" +
                "909192939495969798999A9B9C9D9E9F" +
                "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF" +
                "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" +
                "C0C1C2C3C4C5C6C7");
        byte[] customString = "My Tagged Application".getBytes(StandardCharsets.UTF_8);
        int outputLength = 64;
        byte[] expectedOutput = Hex.decode("B58618F71F92E1D56C1B8C55DDD7CD18" +
                "8B97B4CA4D99831EB2699A837DA2E4D9" +
                "70FBACFDE50033AEA585F1A2708510C3" +
                "2D07880801BD182898FE476876FC8965");
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        byte[] output = Kmac.kmac256(secretKey, data, outputLength, customString);
        assertArrayEquals(expectedOutput, output, "KMAC256 output does not match expected output.");
    }

}