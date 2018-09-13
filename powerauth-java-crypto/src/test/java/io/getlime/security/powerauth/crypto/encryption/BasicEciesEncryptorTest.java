/*
 * Copyright 2016 Wultra s.r.o.
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
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.BasicEciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.BasicEciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.kdf.KdfX9_63;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesPayload;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.Hash;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static org.junit.Assert.*;

/**
 * Test to validate functionality of {@link io.getlime.security.powerauth.crypto.lib.encryptor.ecies.BasicEciesEncryptor}
 * and {@link io.getlime.security.powerauth.crypto.lib.encryptor.ecies.BasicEciesDecryptor} classes.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class BasicEciesEncryptorTest {

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

        byte[] request = "Hello Alice.".getBytes("UTF-8");
        byte[] response = "Hello Bob".getBytes("UTF-8");

        for (int i = 0; i < 100; i++) {

            BasicEciesEncryptor encryptor = new BasicEciesEncryptor((ECPublicKey) publicKey);
            final EciesPayload payloadRequest = encryptor.encrypt(request, null);
            System.out.println("# REQUEST");
            System.out.println("- Original data: " + BaseEncoding.base64().encode(request) + " (" + new String(request, "UTF-8") + ")");
            System.out.println("- Encrypted data: " + BaseEncoding.base64().encode(payloadRequest.getEncryptedData()));
            System.out.println("- MAC: " + BaseEncoding.base64().encode(payloadRequest.getMac()));
            System.out.println("- Ephemeral Public Key: " + BaseEncoding.base64().encode(
                    keyConversion.convertPublicKeyToBytes(
                            payloadRequest.getEphemeralPublicKey()
                    )
            ));
            System.out.println();

            BasicEciesDecryptor decryptor = new BasicEciesDecryptor((ECPrivateKey) privateKey, null);
            final byte[] originalBytesRequest = decryptor.decrypt(payloadRequest, null);

            assertArrayEquals(request, originalBytesRequest);

            final EciesPayload payloadResponse = decryptor.encrypt(response, null);
            System.out.println("# RESPONSE");
            System.out.println("- Original data: " + BaseEncoding.base64().encode(response) + " (" + new String(response, "UTF-8") + ")");
            System.out.println("- Encrypted data: " + BaseEncoding.base64().encode(payloadResponse.getEncryptedData()));
            System.out.println("- MAC: " + BaseEncoding.base64().encode(payloadResponse.getMac()));
            System.out.println("- Ephemeral Public Key: " + BaseEncoding.base64().encode(
                    keyConversion.convertPublicKeyToBytes(
                            payloadResponse.getEphemeralPublicKey()
                    )
            ));
            System.out.println();


            final byte[] originalBytesResponse = encryptor.decrypt(payloadResponse);

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

        byte[] request = "Hello Alice.".getBytes("UTF-8");
        byte[] response = "Hello Bob".getBytes("UTF-8");

        for (int i = 0; i < 5; i++) {

            BasicEciesEncryptor encryptor = new BasicEciesEncryptor((ECPublicKey) publicKey);
            final EciesPayload payloadRequest = encryptor.encrypt(request, null);
            System.out.println("# REQUEST");
            System.out.println("- Original data: " + BaseEncoding.base64().encode(request) + " (" + new String(request, "UTF-8") + ")");
            System.out.println("- Encrypted data: " + BaseEncoding.base64().encode(payloadRequest.getEncryptedData()));
            System.out.println("- MAC: " + BaseEncoding.base64().encode(payloadRequest.getMac()));
            System.out.println("- Ephemeral Public Key: " + BaseEncoding.base64().encode(
                    keyConversion.convertPublicKeyToBytes(
                            payloadRequest.getEphemeralPublicKey()
                    )
            ));
            System.out.println();

            byte[] macBroken = keyGenerator.generateRandomBytes(16);
            EciesPayload broken = new EciesPayload(payloadRequest.getEphemeralPublicKey(), macBroken, payloadRequest.getEncryptedData());

            BasicEciesDecryptor decryptor = new BasicEciesDecryptor((ECPrivateKey) privateKey, null);
            byte[] originalBytesRequest;
            try {
                decryptor.decrypt(broken, null);
                fail("Invalid MAC was provided in request and should have been rejected");
            } catch (EciesException e) {
                // OK
                System.out.println("!!! Invalid MAC correctly detected in request");
                System.out.println();
            }

            originalBytesRequest = decryptor.decrypt(payloadRequest, null);

            assertArrayEquals(request, originalBytesRequest);

            final EciesPayload payloadResponse = decryptor.encrypt(response, null);
            System.out.println("# RESPONSE");
            System.out.println("- Original data: " + BaseEncoding.base64().encode(response) + " (" + new String(response, "UTF-8") + ")");
            System.out.println("- Encrypted data: " + BaseEncoding.base64().encode(payloadResponse.getEncryptedData()));
            System.out.println("- MAC: " + BaseEncoding.base64().encode(payloadResponse.getMac()));
            System.out.println("- Ephemeral Public Key: " + BaseEncoding.base64().encode(
                    keyConversion.convertPublicKeyToBytes(
                            payloadResponse.getEphemeralPublicKey()
                    )
            ));
            System.out.println();

            byte[] macBrokenResponse = keyGenerator.generateRandomBytes(16);
            EciesPayload brokenResponse = new EciesPayload(payloadResponse.getEphemeralPublicKey(), macBrokenResponse, payloadResponse.getEncryptedData());

            byte[] originalBytesResponse;

            try {
                encryptor.decrypt(brokenResponse);
                fail("Invalid MAC was provided in response and should have been rejected");
            } catch (EciesException e) {
                // OK
                System.out.println("!!! Invalid MAC correctly detected in response");
                System.out.println();
            }
            originalBytesResponse = encryptor.decrypt(payloadResponse);

            assertArrayEquals(response, originalBytesResponse);

        }

    }

    /**
     * Test KDF implementation (X9.63 with SHA 256).
     */
    @Test
    public void testKdf() {

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
     * Test that values match client side test vectors.
     * @throws Exception When test fails.
     */
    @Test
    public void testVectors() throws Exception {

        final PrivateKey privateKey = keyConversion.convertBytesToPrivateKey(BaseEncoding.base64().decode("ALNdDn6auRO69TOJGGmK3ZYbCVXa+d5kobWo028vugzd"));
        final PublicKey publicKey = keyConversion.convertBytesToPublicKey(BaseEncoding.base64().decode("A1PS1QVrJBHlLLq7UFv87qtS0Ka2Ou5ehAbCqeSTjSid"));

        byte[][] request = {
                BaseEncoding.base64().decode("aGVsbG8gd29ybGQh"),
                BaseEncoding.base64().decode("QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVzIQ=="),
                BaseEncoding.base64().decode("SXQncyBvdmVyIEpvaG55ISBJdCdzIG92ZXIu"),
                "".getBytes("UTF-8"),
                "".getBytes("UTF-8"),
                "".getBytes("UTF-8")
        };
        byte[][] response = {
                BaseEncoding.base64().decode("aGV5IHRoZXJlIQ=="),
                BaseEncoding.base64().decode("Tk9QRSE="),
                BaseEncoding.base64().decode("Tm90aGluZyBpcyBvdmVyISBOb3RoaW5nISBZb3UganVzdCBkb24ndCB0dXJuIGl0IG9mZiEgSXQgd2Fzbid0IG15IHdhciEgWW91IGFza2VkIG1lLCBJIGRpZG4ndCBhc2sgeW91ISBBbmQgSSBkaWQgd2hhdCBJIGhhZCB0byBkbyB0byB3aW4h"),
                "".getBytes("UTF-8"),
                "".getBytes("UTF-8"),
                "".getBytes("UTF-8")
        };
        byte[][] sharedInfo = {
                "".getBytes("UTF-8"),
                BaseEncoding.base64().decode("dmVyeSBzZWNyZXQgaW5mb3JtYXRpb24="),
                BaseEncoding.base64().decode("MDEyMzQ1Njc4OWFiY2RlZg=="),
                BaseEncoding.base64().decode("MTIzNDUtNTY3ODk="),
                "".getBytes("UTF-8"),
                "".getBytes("UTF-8")
        };
        byte[][] ephemeralPublicKey = {
                BaseEncoding.base64().decode("AtxcLBBO87sdmlGZaapgZCKpUNDxQA4uEGAa5GXVTmSj"),
                BaseEncoding.base64().decode("AqgzPA+rkT8uaYWZOtBnPZL7pK9qD/UvZamWobBVgvLG"),
                BaseEncoding.base64().decode("A4F/ksKE13u5QjzJ5WGPFF1cbWcYG6JCFCQasUEsLQsu"),
                BaseEncoding.base64().decode("A+KiCfhwfdEGCDstnP50X3M/Dp/GtM9DFuqPppF+CR2O"),
                BaseEncoding.base64().decode("A6e+pgj24/QFKilVm11Jm6LH5NdUCSVD57s3CN2PaO8D"),
                BaseEncoding.base64().decode("AoiuMPw8KCmyMBqnIoYTfs+y0lMD3UimHsUrdaaqJmhw")
        };

        EciesPayload[] encryptedRequest = {
                new EciesPayload(
                        keyConversion.convertBytesToPublicKey(ephemeralPublicKey[0]),
                        BaseEncoding.base64().decode("DUClyueyHW3BWS5EcR6h+F6DSxgQZsB+utzcOIGadGA="),
                        BaseEncoding.base64().decode("hw6NQximlwv0oE4e4TD88A==")
                ),
                new EciesPayload(
                        keyConversion.convertBytesToPublicKey(ephemeralPublicKey[1]),
                        BaseEncoding.base64().decode("Zuy1DNzPGZ4UGBQ4OM3suBTX+VobgjIcm6ENCZFCKBA="),
                        BaseEncoding.base64().decode("RAxwKcBykcsZf9fPUEJ+qkfQJ0Kw00IGYc17UfzP978=")
                ),
                new EciesPayload(
                        keyConversion.convertBytesToPublicKey(ephemeralPublicKey[2]),
                        BaseEncoding.base64().decode("dsKrDGIVIyYAmKtm+hMA2yur2hjrQmERODtnNMYJvOA="),
                        BaseEncoding.base64().decode("Q0+RkzSkNfT1D3E2VxVklSt0sdNNY70j3DmtqxXbrvM=")
                ),
                new EciesPayload(
                        keyConversion.convertBytesToPublicKey(ephemeralPublicKey[3]),
                        BaseEncoding.base64().decode("f8nzdA70PeoCLMEcwr32LVqgoilkWOLX5GltuqbKE+8="),
                        BaseEncoding.base64().decode("tIWVnWGfxqEN6juSBL0wBw==")
                ),
                new EciesPayload(
                        keyConversion.convertBytesToPublicKey(ephemeralPublicKey[4]),
                        BaseEncoding.base64().decode("zqwyVtYsLc8HKReIX5YH+bea/bmD9xNBqHlWI3DW4bg="),
                        BaseEncoding.base64().decode("hEUFGO/cyvYwrnPuYfAN5Q==")
                ),
                new EciesPayload(
                        keyConversion.convertBytesToPublicKey(ephemeralPublicKey[5]),
                        BaseEncoding.base64().decode("WfPtqxADasfGPb7P/T6ZIaGPKWF87pdvGKKVDu9vWZc="),
                        BaseEncoding.base64().decode("86SDx6jPqgWejE92hh2zxg==")
                )
        };

        EciesPayload[] encryptedResponse = {
                new EciesPayload(
                        keyConversion.convertBytesToPublicKey(ephemeralPublicKey[0]),
                        BaseEncoding.base64().decode("+geGPQSxID9TM0kdWgqXiur1yOET7WvVgBJu0fXNAmk="),
                        BaseEncoding.base64().decode("+7jbEirkDVAxbLo7DM8V6g==")
                ),
                new EciesPayload(
                        keyConversion.convertBytesToPublicKey(ephemeralPublicKey[1]),
                        BaseEncoding.base64().decode("aqxaDtoXVnm3mkgjlA2bwGupbrONcgNkdrOM1oxtIHM="),
                        BaseEncoding.base64().decode("3wtEfjEt90sIFT1X4+9rYg==")
                ),
                new EciesPayload(
                        keyConversion.convertBytesToPublicKey(ephemeralPublicKey[2]),
                        BaseEncoding.base64().decode("hNQKCoc1g+/PPNOlF+z7Cx3m5bijAekQqHvuWlTzoIg="),
                        BaseEncoding.base64().decode("MpHh1Sx5qofeYjSOrziLw6GyTGAT2929x1XZDZXtjZxHGXYwaUBlnMB5+zF7YsnbIAy/8ZB/8/bWKz0r6Sk/6Gw/e6V7mpR5dKjqVqMBn6ioLRCGBqhyv+Px7BAwHwN1ymfjz5o1aQJo/isdbxZjgIWjfiJc9W3mxFWQ5fGBxC8oPiMlx4SELd6WTWaCwa5E")
                ),
                new EciesPayload(
                        keyConversion.convertBytesToPublicKey(ephemeralPublicKey[3]),
                        BaseEncoding.base64().decode("f8nzdA70PeoCLMEcwr32LVqgoilkWOLX5GltuqbKE+8="),
                        BaseEncoding.base64().decode("tIWVnWGfxqEN6juSBL0wBw==")
                ),
                new EciesPayload(
                        keyConversion.convertBytesToPublicKey(ephemeralPublicKey[4]),
                        BaseEncoding.base64().decode("zqwyVtYsLc8HKReIX5YH+bea/bmD9xNBqHlWI3DW4bg="),
                        BaseEncoding.base64().decode("hEUFGO/cyvYwrnPuYfAN5Q==")
                ),
                new EciesPayload(
                        keyConversion.convertBytesToPublicKey(ephemeralPublicKey[5]),
                        BaseEncoding.base64().decode("WfPtqxADasfGPb7P/T6ZIaGPKWF87pdvGKKVDu9vWZc="),
                        BaseEncoding.base64().decode("86SDx6jPqgWejE92hh2zxg==")
                )
        };

        for (int i = 0; i < request.length; i++) {

            System.out.println("## Test vector: " + i);

            EciesPayload requestPayload = encryptedRequest[i];

            BasicEciesDecryptor decryptor = new BasicEciesDecryptor((ECPrivateKey) privateKey, sharedInfo[i]);

            final byte[] decryptedRequest = decryptor.decrypt(requestPayload, ephemeralPublicKey[i]);
            assertArrayEquals(decryptedRequest, request[i]);

            EciesPayload expectedResponsePayload = encryptedResponse[i];
            final EciesPayload responsePayload = decryptor.encrypt(response[i], ephemeralPublicKey[i]);

            assertArrayEquals(expectedResponsePayload.getEncryptedData(), responsePayload.getEncryptedData());
            assertArrayEquals(expectedResponsePayload.getMac(), responsePayload.getMac());
            assertEquals(expectedResponsePayload.getEphemeralPublicKey(), responsePayload.getEphemeralPublicKey());

        }

    }

}
