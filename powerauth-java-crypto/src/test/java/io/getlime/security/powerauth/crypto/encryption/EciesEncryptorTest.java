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

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.kdf.KdfX9_63;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.*;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.ByteUtils;
import io.getlime.security.powerauth.crypto.lib.util.EciesUtils;
import io.getlime.security.powerauth.crypto.lib.util.Hash;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Date;

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
    private final EciesFactory eciesFactory = new EciesFactory();

    /**
     * Add crypto providers.
     */
    @BeforeAll
    public static void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test that data that go from encryptor can be processed by decryptor and vice versa.
     * @throws Exception When test fails.
     */
    @Test
    public void testEncryptDecrypt() throws Exception {

        final KeyPair fixedKeyPair = keyGenerator.generateKeyPair();
        final ECPrivateKey privateKey = (ECPrivateKey) fixedKeyPair.getPrivate();
        final ECPublicKey publicKey = (ECPublicKey) fixedKeyPair.getPublic();
        final byte[] publicKeyBytes = keyConvertor.convertPublicKeyToBytes(publicKey);

        final byte[] request = "Hello Alice.".getBytes(StandardCharsets.UTF_8);
        final byte[] response = "Hello Bob".getBytes(StandardCharsets.UTF_8);
        final byte[] applicationSecret = "test_secret".getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < 100; i++) {
            byte[] nonceRequest = null;
            Long timestampRequest = null;
            byte[] nonceResponse = null;
            Long timestampResponse = null;
            byte[] associatedData = null;
            if ((i & 1) == 1) {
                // Protocol V3.1+
                nonceRequest = keyGenerator.generateRandomBytes(16);
                nonceResponse = keyGenerator.generateRandomBytes(16);
                if ((i & 2) == 2) {
                    // Protocol V3.2+
                    associatedData = ByteUtils.concatStrings("3.2", "test_secret");
                    timestampRequest = new Date().getTime();
                    timestampResponse = new Date().getTime() + 1;
                }
            }

            final EciesParameters eciesParametersRequest = EciesParameters.builder()
                    .nonce(nonceRequest)
                    .associatedData(associatedData)
                    .timestamp(timestampRequest)
                    .build();
            final EciesEncryptor encryptorRequest = eciesFactory.getEciesEncryptorForApplication(publicKey, applicationSecret, EciesSharedInfo1.APPLICATION_SCOPE_GENERIC, eciesParametersRequest);
            final EciesPayload payloadRequest = encryptorRequest.encrypt(request, eciesParametersRequest);
            final EciesCryptogram cryptogram = payloadRequest.getCryptogram();
            final EciesParameters parameters = payloadRequest.getParameters();
            System.out.println("# REQUEST");
            System.out.println("- Original data: " + Base64.getEncoder().encodeToString(request) + " (" + new String(request, StandardCharsets.UTF_8) + ")");
            System.out.println("- Encrypted data: " + Base64.getEncoder().encodeToString(cryptogram.getEncryptedData()));
            System.out.println("- MAC: " + Base64.getEncoder().encodeToString(cryptogram.getMac()));
            System.out.println("- Nonce: " + (nonceRequest != null ? Base64.getEncoder().encodeToString(parameters.getNonce()) : "null"));
            System.out.println("- Timestamp: " + (timestampRequest != null ? parameters.getTimestamp() : "null"));
            System.out.println("- Associated data: " + (timestampRequest != null ? Base64.getEncoder().encodeToString(parameters.getAssociatedData()) : "null"));
            System.out.println("- Ephemeral public key: " + Base64.getEncoder().encodeToString(cryptogram.getEphemeralPublicKey()));
            System.out.println();

            final EciesDecryptor decryptorRequest = eciesFactory.getEciesDecryptorForApplication(privateKey, applicationSecret, EciesSharedInfo1.APPLICATION_SCOPE_GENERIC,
                    eciesParametersRequest, cryptogram.getEphemeralPublicKey());
            final byte[] originalBytesRequest = decryptorRequest.decrypt(payloadRequest);

            assertArrayEquals(request, originalBytesRequest);

            final EciesParameters eciesParametersResponse = EciesParameters.builder()
                    .nonce(nonceResponse)
                    .associatedData(associatedData)
                    .timestamp(timestampResponse)
                    .build();
            final EciesEncryptor encryptorResponse = eciesFactory.getEciesEncryptor(EciesScope.APPLICATION_SCOPE,
                    decryptorRequest.getEnvelopeKey(), applicationSecret, null, eciesParametersResponse);

            final EciesPayload payloadResponse = encryptorResponse.encrypt(response, eciesParametersResponse);
            System.out.println("# RESPONSE");
            System.out.println("- Original data: " + Base64.getEncoder().encodeToString(response) + " (" + new String(response, StandardCharsets.UTF_8) + ")");
            System.out.println("- Encrypted data: " + Base64.getEncoder().encodeToString(payloadResponse.getCryptogram().getEncryptedData()));
            System.out.println("- MAC: " + Base64.getEncoder().encodeToString(payloadResponse.getCryptogram().getMac()));
            System.out.println("- Nonce: " + (nonceResponse != null ? Base64.getEncoder().encodeToString(payloadResponse.getParameters().getNonce()) : "null"));
            System.out.println("- Timestamp: " + (timestampResponse != null ? payloadResponse.getParameters().getTimestamp() : "null"));
            System.out.println("- Associated data: " + (timestampResponse != null ? Base64.getEncoder().encodeToString(payloadResponse.getParameters().getAssociatedData()) : "null"));
            System.out.println("- Ephemeral public key: " + Base64.getEncoder().encodeToString(payloadResponse.getCryptogram().getEphemeralPublicKey()));
            System.out.println();

            final EciesDecryptor decryptorResponse = eciesFactory.getEciesDecryptor(EciesScope.APPLICATION_SCOPE,
                    encryptorRequest.getEnvelopeKey(), applicationSecret, null, eciesParametersResponse, cryptogram.getEphemeralPublicKey());
            final byte[] originalBytesResponse = decryptorResponse.decrypt(payloadResponse);

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
        final ECPrivateKey privateKey = (ECPrivateKey) fixedKeyPair.getPrivate();
        final ECPublicKey publicKey = (ECPublicKey) fixedKeyPair.getPublic();
        final byte[] publicKeyBytes = keyConvertor.convertPublicKeyToBytes(publicKey);

        final byte[] request = "Hello Alice.".getBytes(StandardCharsets.UTF_8);
        final byte[] response = "Hello Bob".getBytes(StandardCharsets.UTF_8);
        final byte[] applicationSecret = "test_secret".getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < 100; i++) {
            byte[] nonceRequest = null;
            Long timestampRequest = null;
            byte[] nonceResponse = null;
            Long timestampResponse = null;
            byte[] associatedData = null;
            if ((i & 1) == 1) {
                // Protocol V3.1+
                nonceRequest = keyGenerator.generateRandomBytes(16);
                nonceResponse = keyGenerator.generateRandomBytes(16);
                if ((i & 2) == 2) {
                    // Protocol V3.2+
                    associatedData = ByteUtils.concatStrings("3.2", "test_secret");
                    timestampRequest = new Date().getTime();
                    timestampResponse = new Date().getTime() + 1;
                }
            }

            final EciesParameters eciesParametersRequest = EciesParameters.builder()
                    .nonce(nonceRequest)
                    .associatedData(associatedData)
                    .timestamp(timestampRequest)
                    .build();
            final EciesEncryptor encryptorRequest = eciesFactory.getEciesEncryptorForApplication(publicKey, applicationSecret, EciesSharedInfo1.APPLICATION_SCOPE_GENERIC, eciesParametersRequest);
            final EciesPayload payloadRequest = encryptorRequest.encrypt(request, eciesParametersRequest);
            final EciesCryptogram cryptogram = payloadRequest.getCryptogram();
            final EciesParameters parameters = payloadRequest.getParameters();
            System.out.println("# REQUEST");
            System.out.println("- Original data: " + Base64.getEncoder().encodeToString(request) + " (" + new String(request, StandardCharsets.UTF_8) + ")");
            System.out.println("- Encrypted data: " + Base64.getEncoder().encodeToString(cryptogram.getEncryptedData()));
            System.out.println("- MAC: " + Base64.getEncoder().encodeToString(cryptogram.getMac()));
            System.out.println("- Nonce: " + (nonceRequest != null ? Base64.getEncoder().encodeToString(parameters.getNonce()) : "null"));
            System.out.println("- Timestamp: " + (timestampRequest != null ? parameters.getTimestamp() : "null"));
            System.out.println("- Associated data: " + (timestampRequest != null ? Base64.getEncoder().encodeToString(parameters.getAssociatedData()) : "null"));
            System.out.println("- Ephemeral public key: " + Base64.getEncoder().encodeToString(cryptogram.getEphemeralPublicKey()));
            System.out.println();

            final byte[] macBrokenRequest = keyGenerator.generateRandomBytes(16);
            final EciesCryptogram cryptogramBrokenRequest = EciesCryptogram.builder()
                    .ephemeralPublicKey(cryptogram.getEphemeralPublicKey())
                    .encryptedData(cryptogram.getEncryptedData())
                    .mac(macBrokenRequest)
                    .build();
            final EciesPayload payloadBrokenRequest = new EciesPayload(cryptogramBrokenRequest, parameters);
            final EciesDecryptor decryptorRequest = eciesFactory.getEciesDecryptorForApplication(privateKey, applicationSecret, EciesSharedInfo1.APPLICATION_SCOPE_GENERIC,
                    eciesParametersRequest, publicKeyBytes);

            try {
                decryptorRequest.decrypt(payloadBrokenRequest);
                fail("Invalid MAC was provided in request and should have been rejected");
            } catch (EciesException e) {
                // OK
                System.out.println("!!! Invalid MAC correctly detected in request");
                System.out.println();
            }

            final EciesParameters eciesParametersResponse = EciesParameters.builder()
                    .nonce(nonceResponse)
                    .associatedData(associatedData)
                    .timestamp(timestampResponse)
                    .build();
            final EciesEncryptor encryptorResponse = eciesFactory.getEciesEncryptor(EciesScope.APPLICATION_SCOPE,
                    decryptorRequest.getEnvelopeKey(), applicationSecret, null, eciesParametersResponse);

            final EciesPayload payloadResponse = encryptorResponse.encrypt(response, eciesParametersResponse);
            System.out.println("# RESPONSE");
            System.out.println("- Original data: " + Base64.getEncoder().encodeToString(response) + " (" + new String(response, StandardCharsets.UTF_8) + ")");
            System.out.println("- Encrypted data: " + Base64.getEncoder().encodeToString(payloadResponse.getCryptogram().getEncryptedData()));
            System.out.println("- MAC: " + Base64.getEncoder().encodeToString(payloadResponse.getCryptogram().getMac()));
            System.out.println("- Nonce: " + (nonceResponse != null ? Base64.getEncoder().encodeToString(payloadResponse.getParameters().getNonce()) : "null"));
            System.out.println("- Timestamp: " + (timestampResponse != null ? payloadResponse.getParameters().getTimestamp() : "null"));
            System.out.println("- Associated data: " + (timestampResponse != null ? Base64.getEncoder().encodeToString(payloadResponse.getParameters().getAssociatedData()) : "null"));
            System.out.println("- Ephemeral public key: " + Base64.getEncoder().encodeToString(payloadResponse.getCryptogram().getEphemeralPublicKey()));
            System.out.println();

            final byte[] macBrokenResponse = keyGenerator.generateRandomBytes(16);
            final EciesCryptogram cryptogramBrokenResponse = EciesCryptogram.builder()
                    .ephemeralPublicKey(cryptogram.getEphemeralPublicKey())
                    .encryptedData(cryptogram.getEncryptedData())
                    .mac(macBrokenResponse)
                    .build();
            final EciesPayload payloadBrokenResponse = new EciesPayload(cryptogramBrokenResponse, parameters);

            final EciesDecryptor decryptorResponse = eciesFactory.getEciesDecryptor(EciesScope.APPLICATION_SCOPE,
                    decryptorRequest.getEnvelopeKey(), applicationSecret, null, eciesParametersResponse, publicKeyBytes);
            try {
                decryptorResponse.decrypt(payloadBrokenResponse);
                fail("Invalid MAC was provided in response and should have been rejected");
            } catch (EciesException e) {
                // OK
                System.out.println("!!! Invalid MAC correctly detected in response");
                System.out.println();
            }
        }
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

    /**
     * Test for matching client side generated test vectors for ECIES, for protocol V3.2+
     *
     * @throws Exception When test fails.
     */
    @Test
    public void testVectorsV3_2() throws Exception {
        // Paste vectors here (generated by iOS unit tests)
        // ----------------------------
        // Shared constants
        final PrivateKey masterServerPrivateKey = keyConvertor.convertBytesToPrivateKey(ByteUtils.concat(new byte[1], Base64.getDecoder().decode("9yGP2WnAbj+yGAHQyVLYoskZnTu5ohAZgILNbtfd1VA=")));
        final PublicKey masterServerPublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("A+5bma2BQdVwIADKdmIrfjla/Mku/rrqRrivVWdSKExF"));
        final PrivateKey serverPrivateKey = keyConvertor.convertBytesToPrivateKey(ByteUtils.concat(new byte[1], Base64.getDecoder().decode("USng63b1l4Pf5L8As+Ko2l4zbkSRs3ecF6K5N8WQeMc=")));
        final PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("Aoz7sxHbYthkiS3KFJusEaoHkjedL7SgXTKMCzpj0uQE"));
        final String activationId = "E9AA5687-4764-437F-8FB4-A40D199C096A";
        final String applicationKey = "srRZLHZIyzMaN64GJ0dxtA==";
        final String applicationSecret = "ZlOlwx+gLWHb7QpuzxWzAw==";
        final byte[] transportKey = Base64.getDecoder().decode("BsKjSjlaKQOUHtYG98aY1w==");
        // associated data
        final byte[] adApplicationScope = EciesUtils.deriveAssociatedData(EciesScope.APPLICATION_SCOPE, "3.2", applicationKey, null);
        final byte[] adActivationScope = EciesUtils.deriveAssociatedData(EciesScope.ACTIVATION_SCOPE, "3.2", applicationKey, activationId);
        // Original request data
        final byte[][] plainRequestData = {
                Base64.getDecoder().decode("YaU82ZVtxeIGpVVmG6Isi0ONK8L+/39cgtMrNvl0wHU1/5UI6f6Q5wf3lAUQ7Anjsp491JrA/3pUnxgoFeYPgCccU6+km7Nk/IFoGCG+Z9xifMyc0LTKe0QQ"),
                Base64.getDecoder().decode("kInBVi3d3ZXnfarJEzq5IPGzi3VoOxnw+wk3zTbNMp/J/SNWqaADMHk6sLE7Ye3jKHXZPpBI9OtOx94="),
                Base64.getDecoder().decode("yG+hIfLEwOQ5pZ4SlgxtAl5LNj2DUQ+W+PXv1xKTSGe4lPTOBBj3FXhI0ga88dLLeNNFEmc9aU17RoRBwUkQ3p8="),
                Base64.getDecoder().decode("TCZdx+2qrEIEKNhDbwpORPiHshlq4/5bD2/6SFO1DAXk2ulP+BusmZqiVdbu+o69sy0="),
                Base64.getDecoder().decode("ddOilL/cN9r+mb9TMCkj/JYpH08PCuc8uUaGgfcHuBuZ8/lxSbU8OwmkzvR8fLxWs6UmwnvhmtHXhZR02JAQirz5Ti8CMRQ="),
                Base64.getDecoder().decode("/GlPcZzfoI1ouvwyaeb/zDd41ggEUl/tq8BeMQsrQKKqEOw3QZ+kf4DFNez9OW+VFa/UdUSzhXXlRUezBsqO7TwBXyLj9g=="),
                Base64.getDecoder().decode("+HWRrh43RA=="),
                Base64.getDecoder().decode("mvHK5iYUncLZeg=="),
                Base64.getDecoder().decode("HaeoPYvTzpB81Ld2Xqlxc/0vzBMDJvKiFRoO"),
                Base64.getDecoder().decode("56eHMGiTKO+qlf4CvrWkNnJRzz3InPma3tobYsTjHokukBQ9UV8ubJelQZAMxNds/YUbKUfd7dGFO9P/1fzZr+ViIwsY9N8U++sy9Qq0aHp3ZGuG8GQbaze/QU58dlvLTxI="),
                Base64.getDecoder().decode("qftvQ69NTYy4Av48aP7Ha2OiUjI2IxwNCwx+D8WbryU1gwq4wKO+dHpeF2xe1mGWBuWg2gTTF7ABeDG7uPVVHjcAwz7q0SmKsT4cMvFEBU1Vu7m81Y5uxXTQWJbxL1T+tk3dWD3PMu9uD2MaCwRoxI5Tbe3Y"),
                Base64.getDecoder().decode("V016gDqvBDnLLY9pNOHKHrCcBVtiWLpB/iMnVJyFelzWnFCBNz2aH16kB7VVUV9wzGTzUnVcUv+0qtXt9TB+7ru8Be5cBo3ex1owXFHzY9kK3OFPBB7tG4C8OzTOTBG/a9lHQ8HMNBHGEedJWTU7V4d9TyVE"),
                Base64.getDecoder().decode("kvGtv3ETuAP/RlVL6V+WDg8mQTji31elmaqs161/8MIhQuOdJuyBQm4YKKzRUteE7PKJ1jxpCxagwavNjzjHtBHcn1tyvzs1MBCzFHcpwdYp0H6nfsMm1OIvq6d/IOv8OXJNe9JbN/GM7+LI9giT"),
                Base64.getDecoder().decode("vFrd2MCfb2lfp0T9cG9IYEXETLvqacSkS29C08YQj38QtCb641ZLTrjAr1CJm8Rv65xMkjTg+UMQ8cFoFTCxxyI3C1Nhht9+J02UG7gwjpZ6+JJp"),
                Base64.getDecoder().decode("3qk3FhvZsoJZmyIm7IS6cwUvDo0V2g+5GThMfYlsRBFGS3kGp7gaZauDGxhyWwM8B4A70q0T"),
                Base64.getDecoder().decode("Ep+nJI2lx/jzXY76zHXShoQcqZjGxaFvEzasI7dnGEj0UOViwA7hRCLKxNBm7cVtqQ=="),
        };
        // Original response data
        final byte[][] plainResponseData = {
                Base64.getDecoder().decode("sIFW/c6fq/ydsSQq16YqpVadYvsr/4Sb44hPlCMmdTWmYry+srLnN0z75dFw7t7Y2oVlWvbBXFIP4hSMlwb00PW86SDzf1r5CoB5yjM0WpoVc+UopIL+754ovToZKNuWPgMsKBdZXq8="),
                Base64.getDecoder().decode("Rb7GAMGHbUM2cpPrxBTiPS3FnK+MwtHla+uE98XHxUn8YA9w"),
                Base64.getDecoder().decode("AHFix78/UtKb+Bn7RSxY6tFf7nsI3iyrgoVpH9eHhMsj"),
                Base64.getDecoder().decode("8B/4nwcOYVP1+dWqKQRxJZLDqvei8udSJbdv35zB4gbA/OVNwSKB47/YMq/EaEstzCC9majElHOtAHWWEw=="),
                Base64.getDecoder().decode("jNpzHRkMJxSLUGRVGRfZthDsyXZQQWQfh21YQW7cXiKmFhOMbIhQ4jGB1k2wN6OpeQpC2ICAwuZHUkbgjejPd9BAhhs+NJuqXy8zNmxEyw=="),
                Base64.getDecoder().decode("kd+UXlipU5ZD2zWVq4R1+rcWMEEm5E2MJ9V1MvYOdNwu3mOlLe2BiHTxBdL+wWLi0xuTVg=="),
                Base64.getDecoder().decode("JwRK0/bCado7Ia41x44h/r8unR8gulBXIKZwdbU="),
                Base64.getDecoder().decode("aquPESglL5zHJyQzdVttpFmyY+UYeyV5NMmAhwfl9L1NkhfZKMA7p6/6nxcyrQ4FkNGSzxnfMeJiDZaTNGqF"),
                Base64.getDecoder().decode("j2gautpGEjZaQ3jqyin90WAupL2oWzSpagSk8TwZ9ZkXRBGmCnJVe2+sbl4QcO/KLFglY923/sFrqRMFs2l0YhzoLzwo1JbM9x6qNhdxZS58AazApzcZMOUrAOE66ipKlK2Uhhpf2DPkOjs="),
                Base64.getDecoder().decode("M57qIU0guWb+481z5haelp1lnwhxWBBetApaBlN5/wxbyi6hXnfe2tj+uA=="),
                Base64.getDecoder().decode("YpgkE/2U2+syftMpdVXr0PO6iWWlaJpunZiBMvjG9M1RFj5lEP+buxOwZpbQScolGI+uepg="),
                Base64.getDecoder().decode("UFFtPoFH31w7bNbFW9OKpIr4Na6OVB0xQ5AxcNTZRl7Q0EJyaalldNsLXN2/k2ZVIk9yGa8E8mKKNv4d7n5KyzJ2pc1KIOsPFA=="),
                Base64.getDecoder().decode("JiaNh2U4lsXEsizpuHvEErW20zxXCTuQDFlDVf38mrN4PWaksoSFZczVrA=="),
                Base64.getDecoder().decode("44jXTodR6OrLzqUQ1TxBnOl7xlgGoGem4x9e0DM/kWXf/u0bVctxwwnhy3e494CfqyxzzZAjialo/zxfbp9jC9iLQ0GiC+arCxULj06i2BQ="),
                Base64.getDecoder().decode("1JT9CB2D1J+tb2t8scSC4wucgp5thetv5YIOw+6VNABkrmc+mfCTLuOjh46okkIdKNWpyPyfjQVtcsjeCa/f6/wPGl7/LhTLi5dt2D5YGm8IPorKmeFwTQmEY1B5WuBtpZcVZAa8czo1nVavAtDtFw0XpYcH/Q=="),
                Base64.getDecoder().decode("Zs8Za1gQyz3oj+BvGmEGwGqgp0yJfMwETIIyI0B/RXjLFWSHMPiM//gDOTbRPwL+/v6qAcCmHJRAtg8qJ7Crkb1vbXLvGI0="),
        };
        // SharedInfo1s
        final EciesSharedInfo1[] sharedInfo1 = {
                EciesSharedInfo1.APPLICATION_SCOPE_GENERIC,
                EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC,
                EciesSharedInfo1.ACTIVATION_LAYER_2,
                EciesSharedInfo1.UPGRADE,
                EciesSharedInfo1.VAULT_UNLOCK,
                EciesSharedInfo1.CREATE_TOKEN,
                EciesSharedInfo1.CONFIRM_RECOVERY_CODE,
                EciesSharedInfo1.APPLICATION_SCOPE_GENERIC,
                EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC,
                EciesSharedInfo1.ACTIVATION_LAYER_2,
                EciesSharedInfo1.UPGRADE,
                EciesSharedInfo1.VAULT_UNLOCK,
                EciesSharedInfo1.CREATE_TOKEN,
                EciesSharedInfo1.CONFIRM_RECOVERY_CODE,
                EciesSharedInfo1.APPLICATION_SCOPE_GENERIC,
                EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC,
        };
        // Scopes
        final EciesScope[] scopes = {
                EciesScope.ACTIVATION_SCOPE,
                EciesScope.APPLICATION_SCOPE,
                EciesScope.ACTIVATION_SCOPE,
                EciesScope.APPLICATION_SCOPE,
                EciesScope.ACTIVATION_SCOPE,
                EciesScope.APPLICATION_SCOPE,
                EciesScope.ACTIVATION_SCOPE,
                EciesScope.APPLICATION_SCOPE,
                EciesScope.ACTIVATION_SCOPE,
                EciesScope.APPLICATION_SCOPE,
                EciesScope.ACTIVATION_SCOPE,
                EciesScope.APPLICATION_SCOPE,
                EciesScope.ACTIVATION_SCOPE,
                EciesScope.APPLICATION_SCOPE,
                EciesScope.ACTIVATION_SCOPE,
                EciesScope.APPLICATION_SCOPE,
        };
        // Requests
        final EciesPayload[] encryptedRequest = {
                new EciesPayload(
                        Base64.getDecoder().decode("Aga6rckjHaWqSfeEpdeX8cc4ad/eXzt3LJSkQ8MvUfPp"),
                        Base64.getDecoder().decode("gJT858v1R7bILVhERyUNN9w+EOT7eLW4iOb8+RFJRsA="),
                        Base64.getDecoder().decode("o2Tn9uAJVLeB3ic7SJW+yWd++Gt9vaGSBVhOVjDz1i/nxQCzONfc/debc1wY9AYpC7bHXcE3UiO9oFzVkNIs32dGWeDtf7R2yfgrSXAREojR7EeQysUqiYZu+2NZ5ovy"),
                        Base64.getDecoder().decode("CdSWonYj4tw4YzU+vMO20w=="),
                        adActivationScope,
                        1690381157687L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("Ao/CZ4yaBZv6OhJ8uN5qZDiRw1htXMt0/AH9uWbGdi2H"),
                        Base64.getDecoder().decode("zAH1tT9J+PdB28ru53w6pRw8ypQVidZ27uzXvdfrWqY="),
                        Base64.getDecoder().decode("+BKAEnrjI1ObBFjPuyQg54bnEH6G96NFdTiH2z/Fr3dl1m+Mmd4OZwe4x6NOCZBi5Jvk2D5UKIGr5QoPOKv/iw=="),
                        Base64.getDecoder().decode("2Wr3SG2TsSPtBlwEEdkwbw=="),
                        adApplicationScope,
                        1690381157693L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("AgIEqGGgYM42fN4R0b6MRE5jLvLZ2KjkLav5ezwbJ2Hk"),
                        Base64.getDecoder().decode("eyB43ItFhdbE5ryfvDi5U6npDVpaoFktjoLf4/TbAWE="),
                        Base64.getDecoder().decode("kEm6SLHMvPtjqPdFMNV6z7anGQhM1ElBci0ykYG0SDwn2Iau9No0XOJR2HjTLoe0InwLDI8LBeNjVc/H2eK5HSjGbrmqY7N5x/YRIf0jxS8="),
                        Base64.getDecoder().decode("N3zD1mbhpOEih343OpgWuA=="),
                        adActivationScope,
                        1690381157693L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("Ail7ay0PzTo6MzyQd80HhqUBGZxLeT3YU3zPAXzhCUTm"),
                        Base64.getDecoder().decode("xwEtrkOJfZOwcWs6sf0mKBDliZ+aJH/r4DTLB0h4W/s="),
                        Base64.getDecoder().decode("cdSesnMHHb3NyKa/5hzf1GfqyslV2UL4ibp2O0Wlbia9URR4vpyTI8pGpXTA/koPZ2eqRihQR33SiQVFzH9CZA=="),
                        Base64.getDecoder().decode("E9BZmC366C/IzL+NpnXXpA=="),
                        adApplicationScope,
                        1690381157693L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("ApXedOuRHsMGkyHchNof2oYTj3HpZP0NCO1iUDMIenis"),
                        Base64.getDecoder().decode("DvsD6sNJTMwCwuBpridlATGfiS8fy1S8HIenCoCi4kk="),
                        Base64.getDecoder().decode("uqEooezE6vlZe4Zuno7ZMSQ3vtjv8fJsMrBj31YPTVv34ldhnIdUHEpqST9l4+TFWE7EVXAX+Kqv4fSPy4v44z4J9F9SlsIx0f3D//ISrio="),
                        Base64.getDecoder().decode("uPaWIzzG4kk3HhY5ypsOnA=="),
                        adActivationScope,
                        1690381157694L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("AtMwe/j9aw2QeKueOxwO+hc69sEhThxicVSdhBkIVCZG"),
                        Base64.getDecoder().decode("1TgcjlR3AvPbxfDYcrFyZnWPKHXDcux/5EPRV6nDe2M="),
                        Base64.getDecoder().decode("eMd+fBIya7WCXRM+34986ju8fu87VnSIa+rAYHwkNaTMUFD4Q/lE9ZNDXFZXJbvgAdUL8PSi4ZjrWgvNhDJVFqxUk4PFcinfCx6Xdb3KiS8="),
                        Base64.getDecoder().decode("tmN2cCYuIf3OspGH5RPRFA=="),
                        adApplicationScope,
                        1690381157694L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("AxAlsHW08Ne3tAo6099BQflhs6acnjrVN5DAso++fVIe"),
                        Base64.getDecoder().decode("7DXuZ2iGyULntZLHUAmdA5GyOCIxw3adS+eGT5k68fg="),
                        Base64.getDecoder().decode("MwvZ/w7SpBc69EFPAxCNcQ=="),
                        Base64.getDecoder().decode("EgLkH3I0xDLGKmziLlMqMA=="),
                        adActivationScope,
                        1690381157695L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("Awc2xjkKiB8Tk/sHpeL0sctO5/adEGgSrhBLgPZ9AunX"),
                        Base64.getDecoder().decode("pmzcZQRbBqoEctgSEELtioe5Wl3uyG5JD/cRolsU8UQ="),
                        Base64.getDecoder().decode("w41V9kdvu6fNyZY55AwW7Q=="),
                        Base64.getDecoder().decode("e/+I+GxCg2toxhFgJ2nOBA=="),
                        adApplicationScope,
                        1690381157695L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("A+SG4WqpgLHxHwl9Mao4DhjWydhjY2/4vgkeoiZdOw77"),
                        Base64.getDecoder().decode("tJlrtsvQzIGUiy5X3Ge4kYg9fPrtYOJCCI/nQndyPo4="),
                        Base64.getDecoder().decode("hBQLCfRNpHIYbvvVXL2d4N3dhM7iiDMC/itjULciFiw="),
                        Base64.getDecoder().decode("e34gRQOn20tgUMCOemb3uA=="),
                        adActivationScope,
                        1690381157695L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("AlgQH6ZX8DsncUGWjDCdTFKIR01KGDqN5rXhS2+ItXeJ"),
                        Base64.getDecoder().decode("ZBWa2wP0vaKKBhT/PxlzhHpKmZj41k0S9Cg9Zcso8k8="),
                        Base64.getDecoder().decode("kiebHEclX9JMB5A2h+d2UsmZN5rMXvWonVfgjK/iFgo7QShStu0Eb5a0BPKD61JopuhwNQ8unrN+w8l3iwaGEf2+sha9qP2Ru8mF+WcYE0QLfrWywvTIksNEXSfp4aDgnM/BjeoAQjT43+vugfpJhg=="),
                        Base64.getDecoder().decode("JgBGS9Hf9ZSvrKaMTKhsQQ=="),
                        adApplicationScope,
                        1690381157696L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("A24gBzKPxPtT//uKDEiI160TTGhUB7VjTFtR1BcjLhwn"),
                        Base64.getDecoder().decode("6OWAjWa3x4INPK0Y2iIYOsEFNcd0iS4tWkno9Jh5fCg="),
                        Base64.getDecoder().decode("nLQM7CASKSsjIRBwyvDQqFdWvk0Z3WoUtMCntHfM0hp1/dnuWqirsKz9l/c18aqF5wmYPZ4fmsOgiJxyRfVOUAfobcwRSeP1EMylBZ7ssnuIPGxzqpquGU+9tst1dwGhd0i6C9R9Cck7CQ6uncHhhqsqnvP3U/mIVgQRZv6WEvA="),
                        Base64.getDecoder().decode("wNLR9Bc0EEmziXzTavZhhA=="),
                        adActivationScope,
                        1690381157696L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("A/DfHbntszB3ENFcxtGP3xlfm8LFO0dWFa4ercBICbCG"),
                        Base64.getDecoder().decode("0Ws+8YioBLrZuhVDocDL0aGAHPHlMJtKerIR4GqRKoc="),
                        Base64.getDecoder().decode("U25ylC3ssuNQBN+8Qh1iCiByQWCGpIgQqv9Mq5g7vqM6aY0BdLMFYHvZPgwgi/GJudO9jnu+RVm4sLOKBpCRm3m4nedUce8D0adoxVSUj+QYsdRAZi/H77NyqFaO7FnQ05MEA2TL+4EhJjZdAgZfwUhaLGwBz6vWcJ8DWX/GMZM="),
                        Base64.getDecoder().decode("ch+7PDKAM3gpfu58K8IS4w=="),
                        adApplicationScope,
                        1690381157696L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("A1c7kdqAP5VTQxjLNJZ9kmOdfA+Q8gnXuYvfRy47JxCT"),
                        Base64.getDecoder().decode("XWswqkxS7XhScchyvwpOqyUIdhdO/wDTI0ctHUdbGbg="),
                        Base64.getDecoder().decode("hhmAfs/qaE2QXh/I3VXpfsdWe0xYQeCKWGrVGp9t5KlRtd7nEqeTwAbRecziy+v7CmGPBvPYJV2oKDjilhprUHkj44R/wmns8beP3+IFhrOiFytnw4U4FFt/63A3b/5qV0gt/d3L83c8AFkE/5Rvqw=="),
                        Base64.getDecoder().decode("pA+suKUEvjMvuN8MWBt1vg=="),
                        adActivationScope,
                        1690381157697L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("A+ovm/YQ/VNO2ka9dtSVxMzsgU7yB1Bvf0mTm+Bs8h2a"),
                        Base64.getDecoder().decode("Qvl+f82XWeglQ9pRLvHQGgM4xUvWo3IehchYfjcH4AQ="),
                        Base64.getDecoder().decode("khEyzkx5RBy08DF+S2nL7sZ/dtMQjNqnu0dxgx5GfzBeXMFQAV/SkObtZIQQx8dwQRekOAz9yxHoxHhMaT7x/8DKRnKa4zhd6lrNDqGTpV0v6UlLJ3eh0TUCq8LMEPiU"),
                        Base64.getDecoder().decode("xNBFurMWs9Z0HKmSgY1GTw=="),
                        adApplicationScope,
                        1690381157697L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("Apc/A8KReP/zD211szWyOEQ9Eqdz1LCEmJfO1y1HNly8"),
                        Base64.getDecoder().decode("7pao1xEpccSF4vLQWEtwuVsxuUb41UonDDUEdzX+7sk="),
                        Base64.getDecoder().decode("ptjUFFTgI2vYTCKCE4Fd45geQqdZmeP0Pv1Lj1ZD7YaGLi0sepvgxga16p97QuPGk4PN0Y7nXoJPjyxAn8m7pg=="),
                        Base64.getDecoder().decode("133AnnK6YlOJ7USrytCflg=="),
                        adActivationScope,
                        1690381157698L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("Aw2tX6Yc2ktHzGwo5Lon8kmYS2H/Sl27lRf+KCGkc48U"),
                        Base64.getDecoder().decode("ZgvNtZljQLhF+JaQcO371aslra/UkYnMDnJcjrr5O8o="),
                        Base64.getDecoder().decode("oEEBsWR2Vx6BFQWLtHlD4QRJ7qy2GMcUyhub+E6gRhiFy+J8MPyIODbuiZM/LmsesH+bTMBEtIRwPwubRhBN9A=="),
                        Base64.getDecoder().decode("TSCu+xgUquceX7MqfxS5qA=="),
                        adApplicationScope,
                        1690381157698L
                ),
        };
        // Responses
        final EciesPayload[] encryptedResponse = {
                new EciesPayload(
                        Base64.getDecoder().decode("Aga6rckjHaWqSfeEpdeX8cc4ad/eXzt3LJSkQ8MvUfPp"),
                        Base64.getDecoder().decode("0vlwPBdEBZ8+FQwdpR7zrVF5TWhqwxoPaMybukAzyVs="),
                        Base64.getDecoder().decode("D51pr69D8BiRrFZw0QFDpeLlFRH314Eb6ZO186jNqNHVQdvqf8JBX9q+jcx414w60NjaI2Pdv2jUXhzDVqDg/VoRU8F+rw59TiWmOrlmowpUucrgWXPqtD+prSzklgMHoBr44fCck86VmQTZNZg4wQ=="),
                        Base64.getDecoder().decode("/YRyO5KRJHgRsIyubm4P2g=="),
                        adActivationScope,
                        1690381157692L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("Ao/CZ4yaBZv6OhJ8uN5qZDiRw1htXMt0/AH9uWbGdi2H"),
                        Base64.getDecoder().decode("dkYh8FTRICbx4Sft8Q/j6J6pjIpPJ/BvgzGySUk2i20="),
                        Base64.getDecoder().decode("D49D74QuRj/O46Zc3iSsjBul0eQR8PRnUfBlUhBW+lE7g3uSmyIblt4D+N+tY+oy"),
                        Base64.getDecoder().decode("m+GDRcxWm58sFNBYf1Xq2A=="),
                        adApplicationScope,
                        1690381157693L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("AgIEqGGgYM42fN4R0b6MRE5jLvLZ2KjkLav5ezwbJ2Hk"),
                        Base64.getDecoder().decode("AWimw6w/8u5lFnrfYxN/+vwgNp2EVdd1SELRw0TQ4JM="),
                        Base64.getDecoder().decode("ii9ddXP9WPau2DA5Zx98xWFQFbcfHrRKe5DGDqF5BxJrdDWnE6m2pTi0QfKl2FVo"),
                        Base64.getDecoder().decode("9nx9W1k1RJ1535y9mYK7gA=="),
                        adActivationScope,
                        1690381157693L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("Ail7ay0PzTo6MzyQd80HhqUBGZxLeT3YU3zPAXzhCUTm"),
                        Base64.getDecoder().decode("TX438XtBRcd9TZuo7FUWI0fciA87zfF70z4sF3u+tNU="),
                        Base64.getDecoder().decode("YKUtWjzFA4oKPaa1k8Uq+1YE/OdQ2BzihjhxjCVehJRHzdfhQOF0JiT2weSM+J9hosX4RAWgvhdVT6t8c8sMMg=="),
                        Base64.getDecoder().decode("mDAaOxKI3/u5dS6ZmiiAuQ=="),
                        adApplicationScope,
                        1690381157694L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("ApXedOuRHsMGkyHchNof2oYTj3HpZP0NCO1iUDMIenis"),
                        Base64.getDecoder().decode("2qpYb93ULL00grSXmH3r2M0DpyhREbpKs+mFQbcE00A="),
                        Base64.getDecoder().decode("MIDViK4JgnIV3dGMNGJDOaCEbDslmh5MUP/VJJMHGDPPzaYkhXtzsixsNWPQr9HYYCF7jCMFbUtF7D+n3wGnDn2m+HIaynrfBAfN9WUR40c="),
                        Base64.getDecoder().decode("omxDzKPpElTD8eXM7CK9qA=="),
                        adActivationScope,
                        1690381157694L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("AtMwe/j9aw2QeKueOxwO+hc69sEhThxicVSdhBkIVCZG"),
                        Base64.getDecoder().decode("iLtBG1OEJaqed9gzJTnAkzUDRKKf7mVtWkm/cMg4cgo="),
                        Base64.getDecoder().decode("TnRTeNVtY9nwTaT/S5+egPuHmTAICYG+6r8HaO2XnvClBFv3yBVhWDOdsVisvTFCfSWpZ17VN+MjKBpSxMatlg=="),
                        Base64.getDecoder().decode("X8Ofnn1xRt+xfLiHWBef7g=="),
                        adApplicationScope,
                        1690381157694L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("AxAlsHW08Ne3tAo6099BQflhs6acnjrVN5DAso++fVIe"),
                        Base64.getDecoder().decode("6th5DV26C41vOFya0cRzHRtqG56TYV+q//GdmryOXu0="),
                        Base64.getDecoder().decode("up57gzrplQZ87M/UpCZHu7IRa13ARV4YoTBNc8QLFTU="),
                        Base64.getDecoder().decode("VsV+/lmLYRTSmCA+RerYxA=="),
                        adActivationScope,
                        1690381157695L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("Awc2xjkKiB8Tk/sHpeL0sctO5/adEGgSrhBLgPZ9AunX"),
                        Base64.getDecoder().decode("lr9IH4RHGM8VhIgKswRmAXiHkuJNVhFV8VHfMUR1sG4="),
                        Base64.getDecoder().decode("CyOpIAj+mCpuL4281GBt4XBqDiminRJgMqZgYBMaoIbgbbbtOo6NcdGiPePM5gnpG2vozYZ0Gkkx15ULEG9ezw=="),
                        Base64.getDecoder().decode("S/6Xk+J+ZKHsjva/W+QYNg=="),
                        adApplicationScope,
                        1690381157695L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("A+SG4WqpgLHxHwl9Mao4DhjWydhjY2/4vgkeoiZdOw77"),
                        Base64.getDecoder().decode("8/+zgaSyjPRHYHeOt+I6EAdN4TH5TH1pD63S3GFeGqE="),
                        Base64.getDecoder().decode("+3BnOO+Q9XEoGHvVjZs2bx0NQlS2wUnYL/4974NNApKlfj+2f+wd/BBuaANi65Tla4X7fDa5VUzgGFBxQDsBGUzMuZ+EmXi2Q0z3KoszzGdjLa/3hXe+d8Qr/2tg7MT2aSUb1OQ/WUMeSJsneBp5xw=="),
                        Base64.getDecoder().decode("cuBUVF83eioHwlhZtpdVqw=="),
                        adActivationScope,
                        1690381157696L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("AlgQH6ZX8DsncUGWjDCdTFKIR01KGDqN5rXhS2+ItXeJ"),
                        Base64.getDecoder().decode("N7RCD+eXzg1FJtr8GP5o9ODByrI9ColHWIg1nnQNtxw="),
                        Base64.getDecoder().decode("rQyVNqz1pgj3dDxEioc42/SMiPeZVc0nqOb49mmUSJIqZOE9ECey9r5e91bdh97l"),
                        Base64.getDecoder().decode("98TOmmf6o1Xxyu33s1E+oA=="),
                        adApplicationScope,
                        1690381157696L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("A24gBzKPxPtT//uKDEiI160TTGhUB7VjTFtR1BcjLhwn"),
                        Base64.getDecoder().decode("A313Gx/4OVSBm9CejqCY8raFSL7z6v60wI5tcOU+GdY="),
                        Base64.getDecoder().decode("lmhaCH1CyAw8eM3gmsNrWj5fu6YP5gKuHYcIuJkTBdisJLoHdxass7Voahn3xpVbVHQye8p3/6BkUrsEH5ma+g=="),
                        Base64.getDecoder().decode("zH605BoTKrMecRngM65HyA=="),
                        adActivationScope,
                        1690381157696L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("A/DfHbntszB3ENFcxtGP3xlfm8LFO0dWFa4ercBICbCG"),
                        Base64.getDecoder().decode("AyH27WE+M94hp7rIcZlg+1+xwsaYFNPxB6Z4tnthUJk="),
                        Base64.getDecoder().decode("44DwIz0Jtbobb+GTWj2dZGmDXaUyVxhJMx52+RZwXdZmrx+V+S4CZtrwfXWWzfm0HpTbBySkXLBpA1gBDZA+M8TRJ1xtYk6vRQYKWf7Udck="),
                        Base64.getDecoder().decode("HhQrIBZoryQaefXxJW+6DA=="),
                        adApplicationScope,
                        1690381157697L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("A1c7kdqAP5VTQxjLNJZ9kmOdfA+Q8gnXuYvfRy47JxCT"),
                        Base64.getDecoder().decode("I4gJ2UfOe/REFYwFdN3xiiaolzQ1BdbPXIw8ccm1PB4="),
                        Base64.getDecoder().decode("x+qPTNRzRUBjKLdb1G+6vPWVGNRd3R0fNlqLty84DlrQUe3JCJrsJjNQ5M3Z9ssL"),
                        Base64.getDecoder().decode("NhYl5OZYknWpqn+VTtPlvA=="),
                        adActivationScope,
                        1690381157697L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("A+ovm/YQ/VNO2ka9dtSVxMzsgU7yB1Bvf0mTm+Bs8h2a"),
                        Base64.getDecoder().decode("9gckWLgv8P0aYxhqxr+HIEboYxrqcjDtR7cHDAn+zUc="),
                        Base64.getDecoder().decode("pX7C4VFCr1KwYbkYKd+NOmuXcp4vxWTBdN8dOqbt7aJtWHC1DvmQdFRAgfIvMdV7bM9upEeSRfzH861PGTO43heHgoQT1QcDdY3tE1Tz8XXAm+7omTJlD2gPynfJQbNu"),
                        Base64.getDecoder().decode("Zjpn840E4Re6aKXwB8h5fQ=="),
                        adApplicationScope,
                        1690381157697L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("Apc/A8KReP/zD211szWyOEQ9Eqdz1LCEmJfO1y1HNly8"),
                        Base64.getDecoder().decode("MBTtW5Jewq87G2HzRTfFrKdPoAsEtVbk74if9EXbHNU="),
                        Base64.getDecoder().decode("uwD7wRrNrPlatTZjyfx/nnFvSY4J9YjqCUr0apJxqpX5BYSXq9hSihgEFEr2z6oAz7WIe9ckzk0NFt1inZbVtd1sCV38daTjYYYNp+kvHibv14gRJRIcW2yARBoOsBeEpq4kBBYnURjasSoo+Ls3iFaPgHOliV6M38AaeZ6W6+c="),
                        Base64.getDecoder().decode("Oic8pDcxzN7z5pAX9cEMmg=="),
                        adActivationScope,
                        1690381157698L
                ),
                new EciesPayload(
                        Base64.getDecoder().decode("Aw2tX6Yc2ktHzGwo5Lon8kmYS2H/Sl27lRf+KCGkc48U"),
                        Base64.getDecoder().decode("WJpuoz5IPECiyJKqmLSmLt76ATna0q4iErfl0gRlpuw="),
                        Base64.getDecoder().decode("trDHfV6d5pea9+/y3gqrAsJ0f6Lk2MJLn43HZjzBTc/09Gpv+fErWtvqgW4oxtFywU+SDcPBYI/EveTLF/XsuXgsb4LjAolVleQCstDvndI="),
                        Base64.getDecoder().decode("cJ0D3LMsXxEQ5xhhlbCeHA=="),
                        adApplicationScope,
                        1690381157698L
                ),
        };

        // ----------------------------
        // Start of test

        for (int i = 0; i < encryptedRequest.length; i++) {
            // Prepare values for this batch
            final EciesPayload request = encryptedRequest[i];
            final EciesPayload response = encryptedResponse[i];
            final EciesScope scope = scopes[i];
            final EciesSharedInfo1 sh1 = sharedInfo1[i];
            final byte[] appSecret = applicationSecret.getBytes(StandardCharsets.UTF_8);
            // Construct decryptor
            final EciesDecryptor decryptor;
            if (scope == EciesScope.APPLICATION_SCOPE) {
                decryptor = eciesFactory.getEciesDecryptorForApplication((ECPrivateKey) masterServerPrivateKey, appSecret, sh1, request.getParameters(), request.getCryptogram().getEphemeralPublicKey());
            } else {
                decryptor = eciesFactory.getEciesDecryptorForActivation((ECPrivateKey) serverPrivateKey, appSecret, transportKey, sh1, request.getParameters(), request.getCryptogram().getEphemeralPublicKey());
            }
            // Decrypt request and compare to the expected value.
            final byte[] decryptedRequestData = decryptor.decrypt(request);
            assertArrayEquals(plainRequestData[i], decryptedRequestData);
            // Construct encryptor from the decryptor
            final EciesEncryptor encryptor = eciesFactory.getEciesEncryptor(scope, decryptor.getEnvelopeKey(), appSecret, transportKey, response.getParameters());
            // Encrypt the response. We're using already set parameters.
            final EciesPayload encryptedPayload = encryptor.encrypt(plainResponseData[i], response.getParameters());
            // Compare values to expected
            assertArrayEquals(response.getCryptogram().getEncryptedData(), encryptedPayload.getCryptogram().getEncryptedData());
            assertArrayEquals(response.getCryptogram().getMac(), encryptedPayload.getCryptogram().getMac());
            assertArrayEquals(response.getParameters().getNonce(), encryptedPayload.getParameters().getNonce());
            assertEquals(response.getParameters().getTimestamp(), encryptedPayload.getParameters().getTimestamp());
        }
    }
}
