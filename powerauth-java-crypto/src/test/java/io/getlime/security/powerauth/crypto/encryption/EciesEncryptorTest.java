/*
 * PowerAuth Crypto Library
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
package io.getlime.security.powerauth.crypto.encryption;

import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.kdf.KdfX9_63;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.*;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.ByteUtils;
import io.getlime.security.powerauth.crypto.lib.util.Hash;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test to validate functionality of {@link EciesEncryptor}
 * and {@link EciesDecryptor} classes.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EciesEncryptorTest {

    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final EncryptorFactory encryptorFactory = new EncryptorFactory();

    /**
     * Add crypto providers.
     */
    @BeforeAll
    public static void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test KDF implementation (X9.63 with SHA 256).
     */
    @Test
    public void testKdf() throws GenericCryptoException, CryptoProviderException {

        for (int i = 0 ; i < 100 ; i++) {
            final SecretKey secretKey = keyGenerator.generateRandomSecretKey();
            final byte[] secretKeyToBytes = keyConvertor.convertSharedSecretKeyToBytes(secretKey);

            // Implement reference KDF implementation
            final byte[] kdfRef  = KdfX9_63.derive(secretKeyToBytes, null, 32);

            byte[] data = secretKeyToBytes;
            data = ByteUtils.concat(data, ByteBuffer.allocate(4).putInt(1).array());

            final byte[] kdfTriv = Hash.sha256(data);

            assertArrayEquals(kdfTriv, kdfRef);
        }

        // Use NIST test vectors
        // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Component-Testing
        //
        // [SHA-256]
        // [shared secret length = 192]
        // [SharedInfo length = 0]
        // [key data length = 128]
        // TV1:
        byte[] secretBytes = Hex.decode("96c05619d56c328ab95fe84b18264b08725b85e33fd34f08");
        byte[] keyData = Hex.decode("443024c3dae66b95e6f5670601558f71");
        byte[] kdfRef  = KdfX9_63.derive(secretBytes, null, 16);
        assertArrayEquals(keyData, kdfRef);

        // TV2:
        secretBytes = Hex.decode("de4ec3f6b2e9b7b5b6160acd5363c1b1f250e17ee731dbd6");
        keyData = Hex.decode("c8df626d5caaabf8a1b2a3f9061d2420");
        kdfRef  = KdfX9_63.derive(secretBytes, null, 16);
        assertArrayEquals(keyData, kdfRef);

        // TV3:
        secretBytes = Hex.decode("d38bdbe5c4fc164cdd967f63c04fe07b60cde881c246438c");
        keyData = Hex.decode("5e674db971bac20a80bad0d4514dc484");
        kdfRef  = KdfX9_63.derive(secretBytes, null, 16);
        assertArrayEquals(keyData, kdfRef);


        // [SHA-256]
        // [shared secret length = 192]
        // [SharedInfo length = 128]
        // [key data length = 1024]
        // TV1
        secretBytes = Hex.decode("22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d");
        byte[] sharedInfo = Hex.decode("75eef81aa3041e33b80971203d2c0c52");
        keyData = Hex.decode("c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21");
        kdfRef  = KdfX9_63.derive(secretBytes, sharedInfo, 128);
        assertArrayEquals(keyData, kdfRef);

        // TV2
        secretBytes = Hex.decode("7e335afa4b31d772c0635c7b0e06f26fcd781df947d2990a");
        sharedInfo = Hex.decode("d65a4812733f8cdbcdfb4b2f4c191d87");
        keyData = Hex.decode("c0bd9e38a8f9de14c2acd35b2f3410c6988cf02400543631e0d6a4c1d030365acbf398115e51aaddebdc9590664210f9aa9fed770d4c57edeafa0b8c14f93300865251218c262d63dadc47dfa0e0284826793985137e0a544ec80abf2fdf5ab90bdaea66204012efe34971dc431d625cd9a329b8217cc8fd0d9f02b13f2f6b0b");
        kdfRef  = KdfX9_63.derive(secretBytes, sharedInfo, 128);
        assertArrayEquals(keyData, kdfRef);
    }

    /**
     * Test for matching client side generated test vectors for ECIES for protocol V3.0
     *
     * @throws Exception When test fails.
     */
    @Test
    public void testVectorsV3() throws Exception {

        // Add magical 0x0 byte which resolves the sign issue when converting the private key.
        // This issue happens when the BigInteger representing the exported private key is negative (first byte is over 127), like in this case.
        // Newer version of mobile SDK test vector generator should add the 0x0 byte automatically to avoid spending hours over broken private key import...
        byte[] signByte = new byte[1];
        final PrivateKey privateKey = keyConvertor.convertBytesToPrivateKey(ByteUtils.concat(signByte, Base64.getDecoder().decode("w1l1XbpjTOpHQvE+muGcCajD6qy8h4xwdcHkioxD098=")));
        final PublicKey publicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("Am8gztfnuf/yXRoGLZbY3po4QK1+rSqNByvWs51fN0TS"));

        byte[][] request = {
                Base64.getDecoder().decode("aGVsbG8gd29ybGQh"),
                Base64.getDecoder().decode("QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVzIQ=="),
                Base64.getDecoder().decode("SXQncyBvdmVyIEpvaG55ISBJdCdzIG92ZXIu"),
                "".getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode("e30="),
                Base64.getDecoder().decode("e30=")
        };
        byte[][] response = {
                Base64.getDecoder().decode("aGV5IHRoZXJlIQ=="),
                Base64.getDecoder().decode("Tk9QRSE="),
                Base64.getDecoder().decode("Tm90aGluZyBpcyBvdmVyISBOb3RoaW5nISBZb3UganVzdCBkb24ndCB0dXJuIGl0IG9mZiEgSXQgd2Fzbid0IG15IHdhciEgWW91IGFza2VkIG1lLCBJIGRpZG4ndCBhc2sgeW91ISBBbmQgSSBkaWQgd2hhdCBJIGhhZCB0byBkbyB0byB3aW4h"),
                "".getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode("e30="),
                "".getBytes(StandardCharsets.UTF_8)
        };
        byte[][] sharedInfo1 = {
                "".getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode("dmVyeSBzZWNyZXQgaW5mb3JtYXRpb24="),
                Base64.getDecoder().decode("MDEyMzQ1Njc4OWFiY2RlZg=="),
                Base64.getDecoder().decode("MTIzNDUtNTY3ODk="),
                "".getBytes(StandardCharsets.UTF_8),
                "".getBytes(StandardCharsets.UTF_8)
        };
        byte[][] sharedInfo2 = {
                "".getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode("bm90LXNvLXNlY3JldA=="),
                Base64.getDecoder().decode("Sm9obiBUcmFtb250YQ=="),
                Base64.getDecoder().decode("WlgxMjg="),
                "".getBytes(StandardCharsets.UTF_8),
                "".getBytes(StandardCharsets.UTF_8)
        };
        byte[][] ephemeralPublicKey = {
                Base64.getDecoder().decode("AhzMrk7VZ98yCfi4iPw+1ib/e+CraDPy/zix3efvBJHv"),
                Base64.getDecoder().decode("ArKyGliRX064oZHF8kIhA4DK6kvCfJS8G9/2hRGncetK"),
                Base64.getDecoder().decode("AiN9sPbXLHrxj218+4so6Iq+eYDIzKhWAsfUGYp1qxll"),
                Base64.getDecoder().decode("AxlBhx1um2Az3kBgJ/MBWSkC4rVMJie7VdYCeBvy0sbG"),
                Base64.getDecoder().decode("Alt6eIEqdqhYguBW46Ixoo/leN8Pym0zgWKZX2HotYFj"),
                Base64.getDecoder().decode("A8OFtFRZcgpQ8xmA8qGCoKFFphTkNpK0x4i2SRy51eRk")
        };

        EciesPayload[] encryptedRequest = {
                new EciesPayload(
                        ephemeralPublicKey[0],
                        Base64.getDecoder().decode("M1R8d1WtIj7Ch4EY7kfFdEu8+ogX2zfQZmFsQNvLI+k="),
                        Base64.getDecoder().decode("tvhNs0hyb9o4cXxXR8NeHg=="),
                        null
                ),
                new EciesPayload(
                        ephemeralPublicKey[1],
                        Base64.getDecoder().decode("SQAniMR93pr3tVHwCB+C7ocMO7Jo4SdIAgG3FbxKMZQ="),
                        Base64.getDecoder().decode("n8BlIA81qdEh4h/Y53rlrfVodJFB2KoiCXWIKt4JAGc="),
                        null
                ),
                new EciesPayload(
                        ephemeralPublicKey[2],
                        Base64.getDecoder().decode("gtUyhNxO2mEjcJin/qjSskiPvHuD7zku10o3U5sz3pg="),
                        Base64.getDecoder().decode("+mL/+v8LR07Ih1F1FnPGmqI6Emay6ZDBIndWnsZETB0="),
                        null
                ),
                new EciesPayload(
                        ephemeralPublicKey[3],
                        Base64.getDecoder().decode("GOu5tZblRyXGwVNfWioh1UQzpg9Ztq9ysZ29Kkn29f8="),
                        Base64.getDecoder().decode("6DjnlMLj1xDfdnmBGRmFIQ=="),
                        null
                ),
                new EciesPayload(
                        ephemeralPublicKey[4],
                        Base64.getDecoder().decode("ZUAk0lEk5jh73oNhvK9I7nOW0jvkSrLN8IiDGXXIbA0="),
                        Base64.getDecoder().decode("JpHpSRHKUcaLk7oDZO1K5A=="),
                        null
                ),
                new EciesPayload(
                        ephemeralPublicKey[5],
                        Base64.getDecoder().decode("x6K9y6ggWMbfAgD1CWePGP6sj6JHHKgzXvzQiWNpNJA="),
                        Base64.getDecoder().decode("H/DRpFXS38oah/XOpy6mrw=="),
                        null
                )
        };

        EciesPayload[] encryptedResponse = {
                new EciesPayload(
                        ephemeralPublicKey[0],
                        Base64.getDecoder().decode("GMSvl+OhGsSnBVjLp8MozL/H+lh+Nm96ssaOpt+xa5s="),
                        Base64.getDecoder().decode("3Bhf8/hDkuObm3ufbUWdNg=="),
                        null
                ),
                new EciesPayload(
                        ephemeralPublicKey[1],
                        Base64.getDecoder().decode("X7jagQ+WGqGe5nH2gTEutBBi9jF/D2oHXR+Ywcg28F8="),
                        Base64.getDecoder().decode("i2nsyA7WeUFbWNoPGq1WRQ=="),
                        null
                ),
                new EciesPayload(
                        ephemeralPublicKey[2],
                        Base64.getDecoder().decode("Sqb+1Kk5krPJCqDFWK8JNIpvlaIzq3IYW7RBDGgJPdM="),
                        Base64.getDecoder().decode("u9Pz7CL3w7N5oBEvHoOYgheeBjZzSrvBrLgCxIVizqTJjvJ/TLinhnC99uPZM33RTRmU70U/bj2Wx05e9vBUSwxiHW0aHGfBv8li6CeoiPO32W7V6J6wPmjahxyXrECO7GBRz7eGwAXseHnsE5+mw+xQV6fYLBZHHp7062r/NCrnLwZ4UZDvRLS3q9xPf+NZ"),
                        null
                ),
                new EciesPayload(
                        ephemeralPublicKey[3],
                        Base64.getDecoder().decode("GOu5tZblRyXGwVNfWioh1UQzpg9Ztq9ysZ29Kkn29f8="),
                        Base64.getDecoder().decode("6DjnlMLj1xDfdnmBGRmFIQ=="),
                        null
                ),
                new EciesPayload(
                        ephemeralPublicKey[4],
                        Base64.getDecoder().decode("ZUAk0lEk5jh73oNhvK9I7nOW0jvkSrLN8IiDGXXIbA0="),
                        Base64.getDecoder().decode("JpHpSRHKUcaLk7oDZO1K5A=="),
                        null
                ),
                new EciesPayload(
                        ephemeralPublicKey[5],
                        Base64.getDecoder().decode("zjISViFih5CrRXt0H3CLsH7j305OQvZ29+DC/yevLfs="),
                        Base64.getDecoder().decode("KcyCAzCmVVeH7xlUZcXLXw=="),
                        null
                )
        };

        for (int i = 0; i < request.length; i++) {

            System.out.println("## ECIES test vector: " + i);

            EciesPayload requestPayload = encryptedRequest[i];

            EciesDecryptor decryptor = new EciesDecryptor((ECPrivateKey) privateKey, sharedInfo1[i], sharedInfo2[i]);

            final byte[] decryptedRequest = decryptor.decrypt(requestPayload);
            assertArrayEquals(decryptedRequest, request[i]);

            EciesEncryptor encryptor = new EciesEncryptor(decryptor.getEnvelopeKey(), sharedInfo2[i]);
            EciesPayload expectedResponsePayload = encryptedResponse[i];
            // No additional parameters in protocol V3.0, sharedInfo2 is the same for request/response
            EciesParameters parameters = EciesParameters.builder().build();
            final EciesPayload responsePayload = encryptor.encrypt(response[i], parameters);

            assertArrayEquals(expectedResponsePayload.getCryptogram().getEncryptedData(), responsePayload.getCryptogram().getEncryptedData());
            assertArrayEquals(expectedResponsePayload.getCryptogram().getMac(), responsePayload.getCryptogram().getMac());
        }
    }

    /**
     * Test for matching client side generated test vectors for ECIES, for protocol V3.1+
     *
     * @throws Exception When test fails.
     */
    @Test
    public void testVectorsV3_1() throws Exception {

        // Add magical 0x0 byte which resolves the sign issue when converting the private key.
        // This issue happens when the BigInteger representing the exported private key is negative (first byte is over 127), like in this case.
        // Newer version of mobile SDK test vector generator should add the 0x0 byte automatically to avoid spending hours over broken private key import...
        byte[] signByte = new byte[1];
        final PrivateKey privateKey = keyConvertor.convertBytesToPrivateKey(ByteUtils.concat(signByte, Base64.getDecoder().decode("ALr4uyoOk2OY7bN73vzC0DPZerYLhjbFP/T17sn+MwOM")));
        final PublicKey publicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("A8307eCy64gHWt047YeZzPQ6P8ZbC0djHmDr6JGrgJWx"));

        byte[][] request = {
                Base64.getDecoder().decode("aGVsbG8gd29ybGQh"),
                Base64.getDecoder().decode("QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVzIQ=="),
                Base64.getDecoder().decode("SXQncyBvdmVyIEpvaG55ISBJdCdzIG92ZXIu"),
                "".getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode("e30="),
                Base64.getDecoder().decode("e30=")
        };
        byte[][] response = {
                Base64.getDecoder().decode("aGV5IHRoZXJlIQ=="),
                Base64.getDecoder().decode("Tk9QRSE="),
                Base64.getDecoder().decode("Tm90aGluZyBpcyBvdmVyISBOb3RoaW5nISBZb3UganVzdCBkb24ndCB0dXJuIGl0IG9mZiEgSXQgd2Fzbid0IG15IHdhciEgWW91IGFza2VkIG1lLCBJIGRpZG4ndCBhc2sgeW91ISBBbmQgSSBkaWQgd2hhdCBJIGhhZCB0byBkbyB0byB3aW4h"),
                "".getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode("e30="),
                "".getBytes(StandardCharsets.UTF_8)
        };
        byte[][] sharedInfo1 = {
                "".getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode("dmVyeSBzZWNyZXQgaW5mb3JtYXRpb24="),
                Base64.getDecoder().decode("MDEyMzQ1Njc4OWFiY2RlZg=="),
                Base64.getDecoder().decode("MTIzNDUtNTY3ODk="),
                "".getBytes(StandardCharsets.UTF_8),
                "".getBytes(StandardCharsets.UTF_8)
        };
        byte[][] sharedInfo2 = {
                "".getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode("bm90LXNvLXNlY3JldA=="),
                Base64.getDecoder().decode("Sm9obiBUcmFtb250YQ=="),
                Base64.getDecoder().decode("WlgxMjg="),
                "".getBytes(StandardCharsets.UTF_8),
                "".getBytes(StandardCharsets.UTF_8)
        };
        EciesPayload[] encryptedRequest = {
                new EciesPayload(
                        Base64.getDecoder().decode("A8sRqx/VLwqoVtCzVfe/qk9c3soQ0Qqn7MQa66JEsooQ"),
                        Base64.getDecoder().decode("eLJ+JPk6Tu+XFqPl7faJtdsz4Xifxj1+1dqm320Yd6c="),
                        Base64.getDecoder().decode("E4rq1Ekje1sCWnXHpMfXUQ=="),
                        Base64.getDecoder().decode("/TlSg4ufI5RHlq+Pg+lo7A==")
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("A+DPiM1Ax0Re++L9sIJl/5PRs57Kn9+jWC1vfCC6XV22"),
                        Base64.getDecoder().decode("HXLU+J9ngaL4n1CfzqA2gGeR2/ueR2n6q3d6WYZY8yQ="),
                        Base64.getDecoder().decode("d9ClPpIwQk/bNcsIBFHSxaVyv866slbpBwZ4WGxcSr8="),
                        Base64.getDecoder().decode("CxXmHhyF31GeDhiR7GLSVg==")
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("A8fRuHXpaa4DXso8SmgHnMMyscjrVAGq1R1Dj59fqSiL"),
                        Base64.getDecoder().decode("AUApQaTjjuGJeCWP8J/qh9ZvWKvncN91DqPJSrDNM0w="),
                        Base64.getDecoder().decode("rufQnCIBL+n5E3YICTrrQZJVjUoH1PovL5BEPQKDENI="),
                        Base64.getDecoder().decode("+CFO8M60gIwDkh9chdQ98w==")
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("AuvQMBfzI40VlUVbq1FxXh42R9oRljMeod9cr72/KUe9"),
                        Base64.getDecoder().decode("aUIOblPJPBvdvU1ODwpgh3tq64wf0acVODSn9GV3zy0="),
                        Base64.getDecoder().decode("uvaq0kSsNHmdipjVeHvqpQ=="),
                        Base64.getDecoder().decode("heRzz/F1sVK/aTIX9LJEIA==")
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("AnHy5cXlI3PZBDzgkkYWVdccG9oZvVlAKUAdPmOVXFO5"),
                        Base64.getDecoder().decode("ogs4Cj5qw5BNQ/pULEp4gtR/6S++hW7YR3sOTBuRDHY="),
                        Base64.getDecoder().decode("LS8vSt2r3UupkzhskAebPw=="),
                        Base64.getDecoder().decode("F+zQghpwtuxioHA3jWvFoA==")
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("AuCjc3K6XDM+xqnwwmZrlOszg95gHgLzwn56Y98kjlGq"),
                        Base64.getDecoder().decode("fqJZ6k2efCCpuAjBiAYQH3IpAtgO6yt7hFfnpt9N604="),
                        Base64.getDecoder().decode("NiE9TJk0VsXxPb/6zxdGBA=="),
                        Base64.getDecoder().decode("9plefnOayDXfiQrqiIdnww==")
                )
        };

        EciesPayload[] encryptedResponse = {
                new EciesPayload(
                        null,
                        Base64.getDecoder().decode("u2VgJ0Gfz+L3Nf3QHpnmRidczKNX80Nbv9Cs4Bxn4xo="),
                        Base64.getDecoder().decode("4c28lphPgGJIQ87q0BqGNA=="),
                        null
                ),
                new EciesPayload(
                        null,
                        Base64.getDecoder().decode("Mk6p7EqUd6chb68b0nTckNKUZ9NmlHTtTCBGBHqiB0I="),
                        Base64.getDecoder().decode("iZ110EAyTSB8NXVEAaeN8Q=="),
                        null
                ),
                new EciesPayload(
                        null,
                        Base64.getDecoder().decode("M7k84CSmhvyKG6paPbMOydJp0o2pjUuc863puRhGJD8="),
                        Base64.getDecoder().decode("SclHObcsY8FUFWhuiKjiW5A7jPbtzEqyYOYVRPX7+fD7ehGHfnZWuQMRF1ErtYP4AzzSLF4BEmCzfKd1LyshxjUBFPHoUvRuQVhWYhn+XqXI4nUFx4hhxKFqPDea3DLqNFOKE46LZFbtatW6pKrnmwH2qiRs+NKMy9oHb0BRBnv61lmCQtrgUtAezQKfR8qf"),
                        null
                ),
                new EciesPayload(
                        null,
                        Base64.getDecoder().decode("aUIOblPJPBvdvU1ODwpgh3tq64wf0acVODSn9GV3zy0="),
                        Base64.getDecoder().decode("uvaq0kSsNHmdipjVeHvqpQ=="),
                        null
                ),
                new EciesPayload(
                        null,
                        Base64.getDecoder().decode("ogs4Cj5qw5BNQ/pULEp4gtR/6S++hW7YR3sOTBuRDHY="),
                        Base64.getDecoder().decode("LS8vSt2r3UupkzhskAebPw=="),
                        null
                ),
                new EciesPayload(
                        null,
                        Base64.getDecoder().decode("mUYcNE2UlkGYe9ox+pMvj94yNqUBpR1hNbWhCTl+cbI="),
                        Base64.getDecoder().decode("WuGjDlStpC9f++4vIpSXSQ=="),
                        null
                )
        };

        for (int i = 0; i < request.length; i++) {

            EciesPayload requestPayload = encryptedRequest[i];

            EciesDecryptor decryptor = new EciesDecryptor((ECPrivateKey) privateKey, sharedInfo1[i], sharedInfo2[i]);

            final byte[] decryptedRequest = decryptor.decrypt(requestPayload);
            assertArrayEquals(decryptedRequest, request[i]);

            EciesEncryptor encryptor = new EciesEncryptor(decryptor.getEnvelopeKey(), sharedInfo2[i]);
            EciesPayload expectedResponsePayload = encryptedResponse[i];
            EciesParameters parameters = EciesParameters.builder().nonce(encryptedRequest[i].getParameters().getNonce()).build();
            final EciesPayload responsePayload = encryptor.encrypt(response[i], parameters);

            assertArrayEquals(expectedResponsePayload.getCryptogram().getEncryptedData(), responsePayload.getCryptogram().getEncryptedData());
            assertArrayEquals(expectedResponsePayload.getCryptogram().getMac(), responsePayload.getCryptogram().getMac());
        }
    }
}
