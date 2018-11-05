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
package io.getlime.security.powerauth.crypto.activation;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import io.getlime.security.powerauth.provider.exception.CryptoProviderException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import static org.junit.Assert.*;

/**
 *
 * @author petrdvorak
 */
public class PowerAuthActivationTest {

	/**
	 * Add crypto providers.
	 */
	@Before
	public void setUp() {
		// Add Bouncy Castle Security Provider
		Security.addProvider(new BouncyCastleProvider());
		PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());
	}

	/**
	 * Test that the keys are correctly generated.
	 */
	@Test
	public void testGenerateKeys() throws CryptoProviderException {
		CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
		KeyGenerator keyGenerator = new KeyGenerator();
		KeyPair kp = keyGenerator.generateKeyPair();
		System.out.println("Private Key: " + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(kp.getPrivate())));
		System.out.println("Public Key: " + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(kp.getPublic())));
	}

	/**
	 * Test of the complete activation process, orchestration between client and server.
	 *
	 * @throws Exception In case test fails
	 */
	@Test
	public void testActivationProcess() throws Exception {

		System.out.println("TEST: Activation Process");

		// Prepare test data
		KeyGenerator keyGenerator = new KeyGenerator();
		PowerAuthClientActivation clientActivation = new PowerAuthClientActivation();
		PowerAuthServerActivation serverActivation = new PowerAuthServerActivation();
		KeyPair masterKeyPair = keyGenerator.generateKeyPair();

		// Generate master keypair
		PrivateKey masterPrivateKey = masterKeyPair.getPrivate();
		PublicKey masterPublicKey = masterKeyPair.getPublic();

		for (int i = 0; i < 20; i++) {

			// SERVER: Generate data for activation
			String activationId = serverActivation.generateActivationId();
			String activationCode = serverActivation.generateActivationCode();
			String activationIdShort = activationCode.substring(0, 11);
			String activationOtp = activationCode.substring(12);
			byte[] activationSignature = serverActivation.generateActivationSignature(activationCode, masterPrivateKey);
			KeyPair serverKeyPair = serverActivation.generateServerKeyPair();
			PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
			PublicKey serverPublicKey = serverKeyPair.getPublic();

			// CLIENT: Verify activation signature
			boolean activationSignatureOK = clientActivation.verifyActivationCodeSignature(activationCode, activationSignature, masterPublicKey);
			assertTrue(activationSignatureOK);

			// CLIENT: Generate and send public key
			KeyPair deviceKeyPair = clientActivation.generateDeviceKeyPair();
			KeyPair clientEphemeralKeyPair = keyGenerator.generateKeyPair();
			PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
			PublicKey devicePublicKey = deviceKeyPair.getPublic();
			byte[] clientNonce = clientActivation.generateActivationNonce();
			byte[] c_devicePublicKey = clientActivation.encryptDevicePublicKey(
					devicePublicKey, 
					clientEphemeralKeyPair.getPrivate(), 
					masterPublicKey, 
					activationOtp,
					activationIdShort, 
					clientNonce
			);

			// SERVER: Decrypt device public key
			PublicKey decryptedDevicePublicKey = serverActivation.decryptDevicePublicKey(
					c_devicePublicKey, 
					activationIdShort, 
					masterPrivateKey, 
					clientEphemeralKeyPair.getPublic(), 
					activationOtp,
					clientNonce
			);
			assertEquals(devicePublicKey, decryptedDevicePublicKey);

			// SERVER: Encrypt and send encrypted server public and it's signature
			KeyPair ephemeralKeyPair = keyGenerator.generateKeyPair();
			PrivateKey ephemeralPrivateKey = ephemeralKeyPair.getPrivate();
			PublicKey ephemeralPublicKey = ephemeralKeyPair.getPublic();
			byte[] serverNonce = serverActivation.generateActivationNonce();
			byte[] c_serverPublicKey = serverActivation.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOtp, activationIdShort, serverNonce);
			byte[] c_serverPublicKeySignature = serverActivation.computeServerDataSignature(activationId, c_serverPublicKey, masterPrivateKey);

			// CLIENT: Validate server public key signature and decrypt server public key
			boolean serverPublicKeySignatureOK = clientActivation.verifyServerDataSignature(activationId, c_serverPublicKey, c_serverPublicKeySignature, masterPublicKey);
			assertTrue(serverPublicKeySignatureOK);

			PublicKey decryptedServerPublicKey = clientActivation.decryptServerPublicKey(c_serverPublicKey, devicePrivateKey, ephemeralPublicKey, activationOtp, activationIdShort, serverNonce);
			assertEquals(serverPublicKey, decryptedServerPublicKey);

			// CLIENT and SERVER: Compute device public key fingerprint
			String devicePublicKeyFingerprintClient = clientActivation.computeDevicePublicKeyFingerprint(devicePublicKey);
            String devicePublicKeyFingerprintServer = serverActivation.computeDevicePublicKeyFingerprint(decryptedDevicePublicKey);
			assertEquals(devicePublicKeyFingerprintClient, devicePublicKeyFingerprintServer);

			// CLIENT and SERVER: Compute shared master secret
			SecretKey sharedMasterSecretDevice = keyGenerator.computeSharedKey(devicePrivateKey, serverPublicKey);
			SecretKey sharedMasterSecretServer = keyGenerator.computeSharedKey(serverPrivateKey, devicePublicKey);
			assertEquals(sharedMasterSecretDevice, sharedMasterSecretServer);

		}
	}

	/**
	 * Test public key encryption.
	 * 
	 * @throws Exception When test fails.
	 */
	@Test
	public void testActivationGenerate() throws Exception {
		String activationOTP = "CKZ2O-OE544";
		String activationIdShort = "IFA6F-3NPAZ";
		byte[] activationNonce = BaseEncoding.base64().decode("grDwkvXrgfUdKBsqg0xYYw==");
		byte[] publicKeyBytes = BaseEncoding.base64().decode("BJXfJMCANX+T9FzsG6Hi0KTYPN64i7HxMiWoMYPd17DYfBR+IwzOesTh/jj/B3trL9m3O1oODYil+8ssJzDt/QA=");
		byte[] ephemeralPrivateKeyBytes = BaseEncoding.base64().decode("AKeMTtivK/XRiQPhfJYxAw1L62ah4lGTQ4JKqRrr0fnC");
		byte[] masterPublicKey = BaseEncoding.base64().decode("BFOqvpLNi15eHDt8fkFxFe034Buw/i8gR3ax4fKiIQynt5K858oBBYhqLVH8FhNmMnlysnRd2UsPJSQxzoPhEn8=");
		
		CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
		PrivateKey eph = keyConvertor.convertBytesToPrivateKey(ephemeralPrivateKeyBytes);
		PublicKey mpk = keyConvertor.convertBytesToPublicKey(masterPublicKey);

		PublicKey publicKey = PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertBytesToPublicKey(publicKeyBytes);
		PowerAuthClientActivation activation = new PowerAuthClientActivation();

		byte[] cDevicePublicKey = activation.encryptDevicePublicKey(publicKey, eph, mpk, activationOTP, activationIdShort, activationNonce);
		assertArrayEquals(cDevicePublicKey, BaseEncoding.base64().decode("tnAyB0C5I9xblLlFCPONUT4GtABvutPkRvvx2oTeGIuUMAmUYTqJluKn/Zge+vbq+VArIVNYVTd+0yuBZGVtkkd1mTcc2eTDhqZSQJS6mMgmKeCqv64c6E4dm4INOkxh"));
		
	}

	/**
	 * Test that public key fingerprints are correctly computed.
	 *
	 * @throws Exception When test fails.
	 */
	@Test
	public void testPublicKeyFingerprint() throws Exception {

		String[] publicKeysBase64 = {
		        "BLaTpcUMJU3BYuF8kgeQjYUZp3nHrepNzeOp68bJbdcUtayIWDhLVtX5qFkLoXXsMH6UnxEJXaMbGOCN3i8eDOI",
                "BFxZEGvqTOFolI6cvdJLiQZR3vSFfsajfJz6qHiOtDlKp5PcoMkUKlxC7hXUcRnZy9C8e6wHATahy2y5Y5OzOKc=",
                "BFUKKJvx/jhAuqvCHWet0mY42ACPT+eKL54kusaDgcoIgN9OcrFbPFS0wuTIMM65YAcUvkcmW9SjHs7QwKjMGQM="
		};
		String[] publicKeyFingerprint = {
		        "85240323",
                "27352787",
                "52209841"
		};

        PowerAuthClientActivation clientActivation = new PowerAuthClientActivation();
        PowerAuthServerActivation serverActivation = new PowerAuthServerActivation();

        for (int i = 0; i < publicKeyFingerprint.length; i++) {
            byte[] publicKeyBytes = BaseEncoding.base64().decode(publicKeysBase64[i]);
            PublicKey publicKey = PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertBytesToPublicKey(publicKeyBytes);
            final String fingerprintClient = clientActivation.computeDevicePublicKeyFingerprint(publicKey);
            final String fingerprintServer = serverActivation.computeDevicePublicKeyFingerprint(publicKey);
            assertEquals(publicKeyFingerprint[i], fingerprintClient);
            assertEquals(publicKeyFingerprint[i], fingerprintServer);
        }

	}

}
