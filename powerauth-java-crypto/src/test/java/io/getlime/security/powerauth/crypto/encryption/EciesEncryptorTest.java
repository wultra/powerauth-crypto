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

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.kdf.KdfX9_63;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.Hash;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static org.junit.Assert.*;

/**
 * Test to validate functionality of {@link EciesEncryptor}
 * and {@link EciesDecryptor} classes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class EciesEncryptorTest {

    private final KeyGenerator keyGenerator = new KeyGenerator();
    private CryptoProviderUtil keyConversion;

    /**
     * Add crypto providers.
     */
    @Before
    public void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
        PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());
        keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    }

    /**
     * Test that data that go from encryptor can be processed by decryptor and vice versa.
     * @throws Exception When test fails.
     */
    @Test
    public void testEncryptDecrypt() throws Exception {

        final KeyPair fixedKeyPair = keyGenerator.generateKeyPair();
        final PrivateKey privateKey = fixedKeyPair.getPrivate();
        final PublicKey publicKey = fixedKeyPair.getPublic();

        byte[] request = "Hello Alice.".getBytes(StandardCharsets.UTF_8);
        byte[] response = "Hello Bob".getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < 100; i++) {
            final boolean useIV = (i & 1) == 1;
            EciesEncryptor encryptor = new EciesEncryptor((ECPublicKey) publicKey);
            final EciesCryptogram payloadRequest = encryptor.encryptRequest(request, useIV);
            System.out.println("# REQUEST");
            System.out.println("- Original data: " + BaseEncoding.base64().encode(request) + " (" + new String(request, StandardCharsets.UTF_8) + ")");
            System.out.println("- Encrypted data: " + BaseEncoding.base64().encode(payloadRequest.getEncryptedData()));
            System.out.println("- MAC: " + BaseEncoding.base64().encode(payloadRequest.getMac()));
            System.out.println("- NONCE: " + (useIV ? BaseEncoding.base64().encode(payloadRequest.getNonce()) : "null"));
            System.out.println("- Ephemeral Public Key: " + BaseEncoding.base64().encode(payloadRequest.getEphemeralPublicKey()));
            System.out.println();

            EciesDecryptor decryptor = new EciesDecryptor((ECPrivateKey) privateKey);
            final byte[] originalBytesRequest = decryptor.decryptRequest(payloadRequest, useIV);

            assertArrayEquals(request, originalBytesRequest);

            final EciesCryptogram payloadResponse = decryptor.encryptResponse(response);
            System.out.println("# RESPONSE");
            System.out.println("- Original data: " + BaseEncoding.base64().encode(response) + " (" + new String(response, StandardCharsets.UTF_8) + ")");
            System.out.println("- Encrypted data: " + BaseEncoding.base64().encode(payloadResponse.getEncryptedData()));
            System.out.println("- MAC: " + BaseEncoding.base64().encode(payloadResponse.getMac()));
            System.out.println();


            final byte[] originalBytesResponse = encryptor.decryptResponse(payloadResponse);

            assertArrayEquals(response, originalBytesResponse);
        }
    }

    /**
     * Test that invalid MAC causes message rejection.
     * @throws Exception When test fails.
     */
    @Test
    public void testInvalidMacReject() throws Exception {

        final KeyPair fixedKeyPair = keyGenerator.generateKeyPair();
        final PrivateKey privateKey = fixedKeyPair.getPrivate();
        final PublicKey publicKey = fixedKeyPair.getPublic();

        byte[] request = "Hello Alice.".getBytes(StandardCharsets.UTF_8);
        byte[] response = "Hello Bob".getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < 10; i++) {
            final boolean useIV = (i & 1) == 1;
            EciesEncryptor encryptor = new EciesEncryptor((ECPublicKey) publicKey);
            final EciesCryptogram payloadRequest = encryptor.encryptRequest(request, useIV);
            System.out.println("# REQUEST");
            System.out.println("- Original data: " + BaseEncoding.base64().encode(request) + " (" + new String(request, StandardCharsets.UTF_8) + ")");
            System.out.println("- Encrypted data: " + BaseEncoding.base64().encode(payloadRequest.getEncryptedData()));
            System.out.println("- MAC: " + BaseEncoding.base64().encode(payloadRequest.getMac()));
            System.out.println("- Ephemeral Public Key: " + BaseEncoding.base64().encode(payloadRequest.getEphemeralPublicKey()));
            System.out.println();

            byte[] macBroken = keyGenerator.generateRandomBytes(16);
            EciesCryptogram broken = new EciesCryptogram(payloadRequest.getEphemeralPublicKey(), macBroken, payloadRequest.getEncryptedData(), payloadRequest.getNonce());

            EciesDecryptor decryptor = new EciesDecryptor((ECPrivateKey) privateKey);
            byte[] originalBytesRequest;
            try {
                decryptor.decryptRequest(broken, useIV);
                fail("Invalid MAC was provided in request and should have been rejected");
            } catch (EciesException e) {
                // OK
                System.out.println("!!! Invalid MAC correctly detected in request");
                System.out.println();
            }

            originalBytesRequest = decryptor.decryptRequest(payloadRequest, useIV);

            assertArrayEquals(request, originalBytesRequest);

            final EciesCryptogram payloadResponse = decryptor.encryptResponse(response);
            System.out.println("# RESPONSE");
            System.out.println("- Original data: " + BaseEncoding.base64().encode(response) + " (" + new String(response, StandardCharsets.UTF_8) + ")");
            System.out.println("- Encrypted data: " + BaseEncoding.base64().encode(payloadResponse.getEncryptedData()));
            System.out.println("- MAC: " + BaseEncoding.base64().encode(payloadResponse.getMac()));
            System.out.println();

            byte[] macBrokenResponse = keyGenerator.generateRandomBytes(16);
            EciesCryptogram brokenResponse = new EciesCryptogram(payloadResponse.getEphemeralPublicKey(), macBrokenResponse, payloadResponse.getEncryptedData(), payloadResponse.getNonce());

            byte[] originalBytesResponse;

            try {
                encryptor.decryptResponse(brokenResponse);
                fail("Invalid MAC was provided in response and should have been rejected");
            } catch (EciesException e) {
                // OK
                System.out.println("!!! Invalid MAC correctly detected in response");
                System.out.println();
            }
            originalBytesResponse = encryptor.decryptResponse(payloadResponse);

            assertArrayEquals(response, originalBytesResponse);
        }
    }

    /**
     * Test KDF implementation (X9.63 with SHA 256).
     */
    @Test
    public void testKdf() throws GenericCryptoException {

        for (int i = 0 ; i < 100 ; i++) {
            final SecretKey secretKey = keyGenerator.generateRandomSecretKey();
            final byte[] secretKeyToBytes = keyConversion.convertSharedSecretKeyToBytes(secretKey);

            // Implement reference KDF implementation
            final byte[] kdfRef  = KdfX9_63.derive(secretKeyToBytes, null, 32);

            byte[] data = secretKeyToBytes;
            data = Bytes.concat(data, ByteBuffer.allocate(4).putInt(1).array());

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
        final PrivateKey privateKey = keyConversion.convertBytesToPrivateKey(Bytes.concat(signByte, BaseEncoding.base64().decode("w1l1XbpjTOpHQvE+muGcCajD6qy8h4xwdcHkioxD098=")));
        final PublicKey publicKey = keyConversion.convertBytesToPublicKey(BaseEncoding.base64().decode("Am8gztfnuf/yXRoGLZbY3po4QK1+rSqNByvWs51fN0TS"));

        byte[][] request = {
                BaseEncoding.base64().decode("aGVsbG8gd29ybGQh"),
                BaseEncoding.base64().decode("QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVzIQ=="),
                BaseEncoding.base64().decode("SXQncyBvdmVyIEpvaG55ISBJdCdzIG92ZXIu"),
                "".getBytes(StandardCharsets.UTF_8),
                BaseEncoding.base64().decode("e30="),
                BaseEncoding.base64().decode("e30=")
        };
        byte[][] response = {
                BaseEncoding.base64().decode("aGV5IHRoZXJlIQ=="),
                BaseEncoding.base64().decode("Tk9QRSE="),
                BaseEncoding.base64().decode("Tm90aGluZyBpcyBvdmVyISBOb3RoaW5nISBZb3UganVzdCBkb24ndCB0dXJuIGl0IG9mZiEgSXQgd2Fzbid0IG15IHdhciEgWW91IGFza2VkIG1lLCBJIGRpZG4ndCBhc2sgeW91ISBBbmQgSSBkaWQgd2hhdCBJIGhhZCB0byBkbyB0byB3aW4h"),
                "".getBytes(StandardCharsets.UTF_8),
                BaseEncoding.base64().decode("e30="),
                "".getBytes(StandardCharsets.UTF_8)
        };
        byte[][] sharedInfo1 = {
                "".getBytes(StandardCharsets.UTF_8),
                BaseEncoding.base64().decode("dmVyeSBzZWNyZXQgaW5mb3JtYXRpb24="),
                BaseEncoding.base64().decode("MDEyMzQ1Njc4OWFiY2RlZg=="),
                BaseEncoding.base64().decode("MTIzNDUtNTY3ODk="),
                "".getBytes(StandardCharsets.UTF_8),
                "".getBytes(StandardCharsets.UTF_8)
        };
        byte[][] sharedInfo2 = {
                "".getBytes(StandardCharsets.UTF_8),
                BaseEncoding.base64().decode("bm90LXNvLXNlY3JldA=="),
                BaseEncoding.base64().decode("Sm9obiBUcmFtb250YQ=="),
                BaseEncoding.base64().decode("WlgxMjg="),
                "".getBytes(StandardCharsets.UTF_8),
                "".getBytes(StandardCharsets.UTF_8)
        };
        byte[][] ephemeralPublicKey = {
                BaseEncoding.base64().decode("AhzMrk7VZ98yCfi4iPw+1ib/e+CraDPy/zix3efvBJHv"),
                BaseEncoding.base64().decode("ArKyGliRX064oZHF8kIhA4DK6kvCfJS8G9/2hRGncetK"),
                BaseEncoding.base64().decode("AiN9sPbXLHrxj218+4so6Iq+eYDIzKhWAsfUGYp1qxll"),
                BaseEncoding.base64().decode("AxlBhx1um2Az3kBgJ/MBWSkC4rVMJie7VdYCeBvy0sbG"),
                BaseEncoding.base64().decode("Alt6eIEqdqhYguBW46Ixoo/leN8Pym0zgWKZX2HotYFj"),
                BaseEncoding.base64().decode("A8OFtFRZcgpQ8xmA8qGCoKFFphTkNpK0x4i2SRy51eRk")
        };

        EciesCryptogram[] encryptedRequest = {
                new EciesCryptogram(
                        ephemeralPublicKey[0],
                        BaseEncoding.base64().decode("M1R8d1WtIj7Ch4EY7kfFdEu8+ogX2zfQZmFsQNvLI+k="),
                        BaseEncoding.base64().decode("tvhNs0hyb9o4cXxXR8NeHg=="),
                        null
                ),
                new EciesCryptogram(
                        ephemeralPublicKey[1],
                        BaseEncoding.base64().decode("SQAniMR93pr3tVHwCB+C7ocMO7Jo4SdIAgG3FbxKMZQ="),
                        BaseEncoding.base64().decode("n8BlIA81qdEh4h/Y53rlrfVodJFB2KoiCXWIKt4JAGc="),
                        null
                ),
                new EciesCryptogram(
                        ephemeralPublicKey[2],
                        BaseEncoding.base64().decode("gtUyhNxO2mEjcJin/qjSskiPvHuD7zku10o3U5sz3pg="),
                        BaseEncoding.base64().decode("+mL/+v8LR07Ih1F1FnPGmqI6Emay6ZDBIndWnsZETB0="),
                        null
                ),
                new EciesCryptogram(
                        ephemeralPublicKey[3],
                        BaseEncoding.base64().decode("GOu5tZblRyXGwVNfWioh1UQzpg9Ztq9ysZ29Kkn29f8="),
                        BaseEncoding.base64().decode("6DjnlMLj1xDfdnmBGRmFIQ=="),
                        null
                ),
                new EciesCryptogram(
                        ephemeralPublicKey[4],
                        BaseEncoding.base64().decode("ZUAk0lEk5jh73oNhvK9I7nOW0jvkSrLN8IiDGXXIbA0="),
                        BaseEncoding.base64().decode("JpHpSRHKUcaLk7oDZO1K5A=="),
                        null
                ),
                new EciesCryptogram(
                        ephemeralPublicKey[5],
                        BaseEncoding.base64().decode("x6K9y6ggWMbfAgD1CWePGP6sj6JHHKgzXvzQiWNpNJA="),
                        BaseEncoding.base64().decode("H/DRpFXS38oah/XOpy6mrw=="),
                        null
                )
        };

        EciesCryptogram[] encryptedResponse = {
                new EciesCryptogram(
                        ephemeralPublicKey[0],
                        BaseEncoding.base64().decode("GMSvl+OhGsSnBVjLp8MozL/H+lh+Nm96ssaOpt+xa5s="),
                        BaseEncoding.base64().decode("3Bhf8/hDkuObm3ufbUWdNg=="),
                        null
                ),
                new EciesCryptogram(
                        ephemeralPublicKey[1],
                        BaseEncoding.base64().decode("X7jagQ+WGqGe5nH2gTEutBBi9jF/D2oHXR+Ywcg28F8="),
                        BaseEncoding.base64().decode("i2nsyA7WeUFbWNoPGq1WRQ=="),
                        null
                ),
                new EciesCryptogram(
                        ephemeralPublicKey[2],
                        BaseEncoding.base64().decode("Sqb+1Kk5krPJCqDFWK8JNIpvlaIzq3IYW7RBDGgJPdM="),
                        BaseEncoding.base64().decode("u9Pz7CL3w7N5oBEvHoOYgheeBjZzSrvBrLgCxIVizqTJjvJ/TLinhnC99uPZM33RTRmU70U/bj2Wx05e9vBUSwxiHW0aHGfBv8li6CeoiPO32W7V6J6wPmjahxyXrECO7GBRz7eGwAXseHnsE5+mw+xQV6fYLBZHHp7062r/NCrnLwZ4UZDvRLS3q9xPf+NZ"),
                        null
                ),
                new EciesCryptogram(
                        ephemeralPublicKey[3],
                        BaseEncoding.base64().decode("GOu5tZblRyXGwVNfWioh1UQzpg9Ztq9ysZ29Kkn29f8="),
                        BaseEncoding.base64().decode("6DjnlMLj1xDfdnmBGRmFIQ=="),
                        null
                ),
                new EciesCryptogram(
                        ephemeralPublicKey[4],
                        BaseEncoding.base64().decode("ZUAk0lEk5jh73oNhvK9I7nOW0jvkSrLN8IiDGXXIbA0="),
                        BaseEncoding.base64().decode("JpHpSRHKUcaLk7oDZO1K5A=="),
                        null
                ),
                new EciesCryptogram(
                        ephemeralPublicKey[5],
                        BaseEncoding.base64().decode("zjISViFih5CrRXt0H3CLsH7j305OQvZ29+DC/yevLfs="),
                        BaseEncoding.base64().decode("KcyCAzCmVVeH7xlUZcXLXw=="),
                        null
                )
        };

        for (int i = 0; i < request.length; i++) {

            System.out.println("## ECIES test vector: " + i);

            EciesCryptogram requestPayload = encryptedRequest[i];

            EciesDecryptor decryptor = new EciesDecryptor((ECPrivateKey) privateKey, sharedInfo1[i], sharedInfo2[i]);

            final byte[] decryptedRequest = decryptor.decryptRequest(requestPayload, false);
            assertArrayEquals(decryptedRequest, request[i]);

            EciesCryptogram expectedResponsePayload = encryptedResponse[i];
            final EciesCryptogram responsePayload = decryptor.encryptResponse(response[i]);

            assertArrayEquals(expectedResponsePayload.getEncryptedData(), responsePayload.getEncryptedData());
            assertArrayEquals(expectedResponsePayload.getMac(), responsePayload.getMac());
        }
    }

    /**
     * Test for matching client side generated test vectors for ECIES, for protocol V3.1+
     *
     * @throws Exception When test fails.
     */
    @Test
    public void testVectorsV3_1() throws Exception {

        final BaseEncoding b64 = BaseEncoding.base64();
        // Add magical 0x0 byte which resolves the sign issue when converting the private key.
        // This issue happens when the BigInteger representing the exported private key is negative (first byte is over 127), like in this case.
        // Newer version of mobile SDK test vector generator should add the 0x0 byte automatically to avoid spending hours over broken private key import...
        byte[] signByte = new byte[1];
        final PrivateKey privateKey = keyConversion.convertBytesToPrivateKey(Bytes.concat(signByte, b64.decode("ALr4uyoOk2OY7bN73vzC0DPZerYLhjbFP/T17sn+MwOM")));
        final PublicKey publicKey = keyConversion.convertBytesToPublicKey(b64.decode("A8307eCy64gHWt047YeZzPQ6P8ZbC0djHmDr6JGrgJWx"));

        byte[][] request = {
                b64.decode("aGVsbG8gd29ybGQh"),
                b64.decode("QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVzIQ=="),
                b64.decode("SXQncyBvdmVyIEpvaG55ISBJdCdzIG92ZXIu"),
                "".getBytes(StandardCharsets.UTF_8),
                b64.decode("e30="),
                b64.decode("e30=")
        };
        byte[][] response = {
                b64.decode("aGV5IHRoZXJlIQ=="),
                b64.decode("Tk9QRSE="),
                b64.decode("Tm90aGluZyBpcyBvdmVyISBOb3RoaW5nISBZb3UganVzdCBkb24ndCB0dXJuIGl0IG9mZiEgSXQgd2Fzbid0IG15IHdhciEgWW91IGFza2VkIG1lLCBJIGRpZG4ndCBhc2sgeW91ISBBbmQgSSBkaWQgd2hhdCBJIGhhZCB0byBkbyB0byB3aW4h"),
                "".getBytes(StandardCharsets.UTF_8),
                b64.decode("e30="),
                "".getBytes(StandardCharsets.UTF_8)
        };
        byte[][] sharedInfo1 = {
                "".getBytes(StandardCharsets.UTF_8),
                b64.decode("dmVyeSBzZWNyZXQgaW5mb3JtYXRpb24="),
                b64.decode("MDEyMzQ1Njc4OWFiY2RlZg=="),
                b64.decode("MTIzNDUtNTY3ODk="),
                "".getBytes(StandardCharsets.UTF_8),
                "".getBytes(StandardCharsets.UTF_8)
        };
        byte[][] sharedInfo2 = {
                "".getBytes(StandardCharsets.UTF_8),
                b64.decode("bm90LXNvLXNlY3JldA=="),
                b64.decode("Sm9obiBUcmFtb250YQ=="),
                b64.decode("WlgxMjg="),
                "".getBytes(StandardCharsets.UTF_8),
                "".getBytes(StandardCharsets.UTF_8)
        };
        EciesCryptogram[] encryptedRequest = {
                new EciesCryptogram(
                        b64.decode("A8sRqx/VLwqoVtCzVfe/qk9c3soQ0Qqn7MQa66JEsooQ"),
                        b64.decode("eLJ+JPk6Tu+XFqPl7faJtdsz4Xifxj1+1dqm320Yd6c="),
                        b64.decode("E4rq1Ekje1sCWnXHpMfXUQ=="),
                        b64.decode("/TlSg4ufI5RHlq+Pg+lo7A==")
                ),
                new EciesCryptogram(
                        b64.decode("A+DPiM1Ax0Re++L9sIJl/5PRs57Kn9+jWC1vfCC6XV22"),
                        b64.decode("HXLU+J9ngaL4n1CfzqA2gGeR2/ueR2n6q3d6WYZY8yQ="),
                        b64.decode("d9ClPpIwQk/bNcsIBFHSxaVyv866slbpBwZ4WGxcSr8="),
                        b64.decode("CxXmHhyF31GeDhiR7GLSVg==")
                ),
                new EciesCryptogram(
                        b64.decode("A8fRuHXpaa4DXso8SmgHnMMyscjrVAGq1R1Dj59fqSiL"),
                        b64.decode("AUApQaTjjuGJeCWP8J/qh9ZvWKvncN91DqPJSrDNM0w="),
                        b64.decode("rufQnCIBL+n5E3YICTrrQZJVjUoH1PovL5BEPQKDENI="),
                        b64.decode("+CFO8M60gIwDkh9chdQ98w==")
                ),
                new EciesCryptogram(
                        b64.decode("AuvQMBfzI40VlUVbq1FxXh42R9oRljMeod9cr72/KUe9"),
                        b64.decode("aUIOblPJPBvdvU1ODwpgh3tq64wf0acVODSn9GV3zy0="),
                        b64.decode("uvaq0kSsNHmdipjVeHvqpQ=="),
                        b64.decode("heRzz/F1sVK/aTIX9LJEIA==")
                ),
                new EciesCryptogram(
                        b64.decode("AnHy5cXlI3PZBDzgkkYWVdccG9oZvVlAKUAdPmOVXFO5"),
                        b64.decode("ogs4Cj5qw5BNQ/pULEp4gtR/6S++hW7YR3sOTBuRDHY="),
                        b64.decode("LS8vSt2r3UupkzhskAebPw=="),
                        b64.decode("F+zQghpwtuxioHA3jWvFoA==")
                ),
                new EciesCryptogram(
                        b64.decode("AuCjc3K6XDM+xqnwwmZrlOszg95gHgLzwn56Y98kjlGq"),
                        b64.decode("fqJZ6k2efCCpuAjBiAYQH3IpAtgO6yt7hFfnpt9N604="),
                        b64.decode("NiE9TJk0VsXxPb/6zxdGBA=="),
                        b64.decode("9plefnOayDXfiQrqiIdnww==")
                )        };

        EciesCryptogram[] encryptedResponse = {
                new EciesCryptogram(
                        null,
                        b64.decode("u2VgJ0Gfz+L3Nf3QHpnmRidczKNX80Nbv9Cs4Bxn4xo="),
                        b64.decode("4c28lphPgGJIQ87q0BqGNA=="),
                        null
                ),
                new EciesCryptogram(
                        null,
                        b64.decode("Mk6p7EqUd6chb68b0nTckNKUZ9NmlHTtTCBGBHqiB0I="),
                        b64.decode("iZ110EAyTSB8NXVEAaeN8Q=="),
                        null
                ),
                new EciesCryptogram(
                        null,
                        b64.decode("M7k84CSmhvyKG6paPbMOydJp0o2pjUuc863puRhGJD8="),
                        b64.decode("SclHObcsY8FUFWhuiKjiW5A7jPbtzEqyYOYVRPX7+fD7ehGHfnZWuQMRF1ErtYP4AzzSLF4BEmCzfKd1LyshxjUBFPHoUvRuQVhWYhn+XqXI4nUFx4hhxKFqPDea3DLqNFOKE46LZFbtatW6pKrnmwH2qiRs+NKMy9oHb0BRBnv61lmCQtrgUtAezQKfR8qf"),
                        null
                ),
                new EciesCryptogram(
                        null,
                        b64.decode("aUIOblPJPBvdvU1ODwpgh3tq64wf0acVODSn9GV3zy0="),
                        b64.decode("uvaq0kSsNHmdipjVeHvqpQ=="),
                        null
                ),
                new EciesCryptogram(
                        null,
                        b64.decode("ogs4Cj5qw5BNQ/pULEp4gtR/6S++hW7YR3sOTBuRDHY="),
                        b64.decode("LS8vSt2r3UupkzhskAebPw=="),
                        null
                ),
                new EciesCryptogram(
                        null,
                        b64.decode("mUYcNE2UlkGYe9ox+pMvj94yNqUBpR1hNbWhCTl+cbI="),
                        b64.decode("WuGjDlStpC9f++4vIpSXSQ=="),
                        null
                )
        };

        for (int i = 0; i < request.length; i++) {

            EciesCryptogram requestPayload = encryptedRequest[i];

            EciesDecryptor decryptor = new EciesDecryptor((ECPrivateKey) privateKey, sharedInfo1[i], sharedInfo2[i]);

            final byte[] decryptedRequest = decryptor.decryptRequest(requestPayload);
            assertArrayEquals(decryptedRequest, request[i]);

            EciesCryptogram expectedResponsePayload = encryptedResponse[i];
            final EciesCryptogram responsePayload = decryptor.encryptResponse(response[i]);

            assertArrayEquals(expectedResponsePayload.getEncryptedData(), responsePayload.getEncryptedData());
            assertArrayEquals(expectedResponsePayload.getMac(), responsePayload.getMac());
        }
    }

}
