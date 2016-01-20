/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.activation;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;
import io.getlime.security.powerauth.server.activation.PowerAuthServerActivation;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author petrdvorak
 */
public class PowerAuthActivationTest {

	@BeforeClass
	public static void setUpClass() {
	}

	@AfterClass
	public static void tearDownClass() {
	}

	@Before
	public void setUp() {
		// Add Bouncy Castle Security Provider
		Security.addProvider(new BouncyCastleProvider());
	}

	@After
	public void tearDown() {
	}

	@Test
	public void testGenerateKeys() throws Exception {
		KeyConversionUtils keyConversion = new KeyConversionUtils();
		KeyGenerator keyGenerator = new KeyGenerator();
		KeyPair kp = keyGenerator.generateKeyPair();
		System.out.println("Private Key: " + BaseEncoding.base64().encode(keyConversion.convertPrivateKeyToBytes(kp.getPrivate())));
		System.out.println("Public Key: " + BaseEncoding.base64().encode(keyConversion.convertPublicKeyToBytes(kp.getPublic())));
	}

	/**
	 * Test of the complete activation process, orchestration between client and server.
	 *
	 * @throws java.lang.Exception
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
			@SuppressWarnings("unused")
			String activationId = serverActivation.generateActivationId();
			String activationIdShort = serverActivation.generateActivationIdShort();
			String activationOTP = serverActivation.generateActivationOTP();
			byte[] activationSignature = serverActivation.generateActivationSignature(activationIdShort, activationOTP, masterPrivateKey);
			KeyPair serverKeyPair = serverActivation.generateServerKeyPair();
			PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
			PublicKey serverPublicKey = serverKeyPair.getPublic();

			// CLIENT: Verify activation signature
			boolean activationSignatureOK = clientActivation.verifyActivationDataSignature(activationIdShort, activationOTP, activationSignature, masterPublicKey);
			assertTrue(activationSignatureOK);

			// CLIENT: Generate and send public key
			KeyPair deviceKeyPair = clientActivation.generateDeviceKeyPair();
			PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
			PublicKey devicePublicKey = deviceKeyPair.getPublic();
			byte[] clientNonce = clientActivation.generateActivationNonce();
			byte[] c_devicePublicKey = clientActivation.encryptDevicePublicKey(devicePublicKey, activationOTP, activationIdShort, clientNonce);

			// SERVER: Decrypt device public key
			PublicKey decryptedDevicePublicKey = serverActivation.decryptDevicePublicKey(c_devicePublicKey, activationIdShort, activationOTP, clientNonce);
			assertEquals(devicePublicKey, decryptedDevicePublicKey);

			// SERVER: Encrypt and send encrypted server public and it's signature
			KeyPair ephemeralKeyPair = keyGenerator.generateKeyPair();
			PrivateKey ephemeralPrivateKey = ephemeralKeyPair.getPrivate();
			PublicKey ephemeralPublicKey = ephemeralKeyPair.getPublic();
			byte[] serverNonce = serverActivation.generateActivationNonce();
			byte[] c_serverPublicKey = serverActivation.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOTP, activationIdShort, serverNonce);
			byte[] c_serverPublicKeySignature = serverActivation.computeServerPublicKeySignature(c_serverPublicKey, masterPrivateKey);

			// CLIENT: Validate server public key signature and decrypt server public key
			boolean serverPublicKeySignatureOK = clientActivation.verifyServerPublicKeySignature(c_serverPublicKey, c_serverPublicKeySignature, masterPublicKey);
			assertTrue(serverPublicKeySignatureOK);

			PublicKey decryptedServerPublicKey = clientActivation.decryptServerPublicKey(c_serverPublicKey, devicePrivateKey, ephemeralPublicKey, activationOTP, activationIdShort, serverNonce);
			assertEquals(serverPublicKey, decryptedServerPublicKey);

			// CLIENT and SERVER: Compute device public key fingerprint
			int devicePublicKeyFingerprintClient = clientActivation.computeDevicePublicKeyFingerprint(devicePublicKey);
			int devicePublicKeyFingerprintServer = serverActivation.computeDevicePublicKeyFingerprint(decryptedDevicePublicKey);
			assertEquals(devicePublicKeyFingerprintClient, devicePublicKeyFingerprintServer);

			// CLIENT and SERVER: Compute shared master secret
			SecretKey sharedMasterSecretDevice = keyGenerator.computeSharedKey(devicePrivateKey, serverPublicKey);
			SecretKey sharedMasterSecretServer = keyGenerator.computeSharedKey(serverPrivateKey, devicePublicKey);
			assertEquals(sharedMasterSecretDevice, sharedMasterSecretServer);

		}
	}

	@Test
	public void testActivationGenerate() throws Exception {
		String activationOTP = "CKZ2O-OE544";
		String activationIdShort = "IFA6F-3NPAZ";
		byte[] activationNonce = BaseEncoding.base64().decode("grDwkvXrgfUdKBsqg0xYYw==");
		byte[] publicKeyBytes = BaseEncoding.base64().decode("BJXfJMCANX+T9FzsG6Hi0KTYPN64i7HxMiWoMYPd17DYfBR+IwzOesTh/jj/B3trL9m3O1oODYil+8ssJzDt/QA=");

		PublicKey publicKey = new KeyConversionUtils().convertBytesToPublicKey(publicKeyBytes);
		PowerAuthClientActivation activation = new PowerAuthClientActivation();

		byte[] cDevicePublicKey = activation.encryptDevicePublicKey(publicKey, activationOTP, activationIdShort, activationNonce);
		assertArrayEquals(cDevicePublicKey, BaseEncoding.base64().decode("el8ZgYcenmCPsu2eITa4T/cmTwFxKbHRotmEW0veOyi81RSBPCy4n/WZTOFvvHdIM/IUwUyBTI8+xjKcQ9g14RUuwvnxwqbH3DoMEDWKAx8="));
		
//		System.out.println("[");
//
//		int max = 20;
//		for (int i = 0; i < max; i++) {
//			activationOTP = new IdentifierGenerator().generateActivationIdShort();
//			activationIdShort = new IdentifierGenerator().generateActivationOTP();
//			activationNonce = activation.generateActivationNonce();
//			publicKey = new KeyGenerator().generateKeyPair().getPublic();
//			
//			cDevicePublicKey = activation.encryptDevicePublicKey(publicKey, activationOTP, activationIdShort, activationNonce);
//			
//			System.out.println("    {");			
//			System.out.println("        \"input\": {");
//			System.out.println("            \"activationIdShort\": \"" + activationIdShort + "\",");
//			System.out.println("            \"activationOtp\": \"" + activationOTP + "\",");
//			System.out.println("            \"activationNonce\": \"" + BaseEncoding.base64().encode(activationNonce) + "\",");
//			System.out.println("            \"publicKeyBytes\": \"" + BaseEncoding.base64().encode(new KeyConversionUtils().convertPublicKeyToBytes(publicKey)) + "\"");
//			System.out.println("        },");
//			System.out.println("        \"output\": \"" + BaseEncoding.base64().encode(cDevicePublicKey) + "\"");
//			if (i == max - 1) {
//				System.out.println("    }");
//			} else {
//				System.out.println("    },");
//			}
//		}
//		
//		System.out.println("]");
	}
	
	@Test
	public void testActivationInit() throws Exception {
		String activationOTP;
		String activationIdShort;
		
		PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

		System.out.println("ActivationSignature>> [");

		int max = 20;
		for (int i = 0; i < max; i++) {
			activationOTP = new IdentifierGenerator().generateActivationIdShort();
			activationIdShort = new IdentifierGenerator().generateActivationOTP();
			
			KeyPair kp = activationServer.generateServerKeyPair();
			PrivateKey masterPrivateKey = kp.getPrivate();
			PublicKey masterPublicKey = kp.getPublic();
			
			byte[] activationSignature = activationServer.generateActivationSignature(activationIdShort, activationOTP, masterPrivateKey);
			
			System.out.println("    {");			
			System.out.println("        \"input\": {");
			System.out.println("            \"activationIdShort\": \"" + activationIdShort + "\",");
			System.out.println("            \"activationOtp\": \"" + activationOTP + "\",");
			System.out.println("            \"masterPrivateKey\": \"" + BaseEncoding.base64().encode(new KeyConversionUtils().convertPrivateKeyToBytes(masterPrivateKey)) + "\",");
			System.out.println("            \"masterPublicKey\": \"" + BaseEncoding.base64().encode(new KeyConversionUtils().convertPublicKeyToBytes(masterPublicKey)) + "\"");
			System.out.println("        },");
			System.out.println("        \"output\": {");
			System.out.println("            \"activationSignature\": \"" + BaseEncoding.base64().encode(activationSignature) + "\"");
			System.out.println("        }");
			if (i == max - 1) {
				System.out.println("    }");
			} else {
				System.out.println("    },");
			}
		}
		
		System.out.println("]");
	}
	
	@Test
	public void testActivationAccept() throws Exception {
		String activationOTP = null;
		String activationIdShort = null;
		byte[] activationNonce = null;
		PrivateKey serverPrivateKey = null;
		PublicKey serverPublicKey = null;
		byte[] cServerPublicKey = null;
		
		PublicKey devicePublicKey = null;
		PrivateKey devicePrivateKey = null;
		
		PublicKey ephemeralPublicKey = null;
		PrivateKey ephemeralPrivateKey = null;
		
		PowerAuthServerActivation activationServer = new PowerAuthServerActivation();
		PowerAuthClientActivation activationClient = new PowerAuthClientActivation();
		
		System.out.println("[");
		
		int max = 20;
		for (int i = 0; i < max; i++) {
			
			activationIdShort = new IdentifierGenerator().generateActivationIdShort();
			activationOTP = new IdentifierGenerator().generateActivationOTP();
			activationNonce = activationServer.generateActivationNonce();
			
			KeyPair kp = activationClient.generateDeviceKeyPair();
			devicePrivateKey = kp.getPrivate();
			devicePublicKey = kp.getPublic();
			
			kp = activationServer.generateServerKeyPair();
			serverPrivateKey = kp.getPrivate();
			serverPublicKey = kp.getPublic();
			
			kp = activationServer.generateServerKeyPair();
			ephemeralPrivateKey = kp.getPrivate();
			ephemeralPublicKey = kp.getPublic();
			
			cServerPublicKey = activationServer.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOTP, activationIdShort, activationNonce);
			KeyConversionUtils kcu = new KeyConversionUtils();
			
			System.out.println("    {");			
			System.out.println("        \"input\": {");
			System.out.println("            \"activationIdShort\": \"" + activationIdShort + "\",");
			System.out.println("            \"activationOtp\": \"" + activationOTP + "\",");
			System.out.println("            \"activationNonce\": \"" + BaseEncoding.base64().encode(activationNonce) + "\",");
			System.out.println("            \"devicePrivateKey\": \"" + BaseEncoding.base64().encode(kcu.convertPrivateKeyToBytes(devicePrivateKey)) + "\",");
			System.out.println("            \"devicePublicKey\": \"" + BaseEncoding.base64().encode(kcu.convertPublicKeyToBytes(devicePublicKey)) + "\",");
			System.out.println("            \"encryptedServerPublicKey\": \"" + BaseEncoding.base64().encode(cServerPublicKey) + "\",");
			System.out.println("            \"ephemeralPublicKey\": \"" + BaseEncoding.base64().encode(kcu.convertPublicKeyToBytes(ephemeralPublicKey)) + "\"");
			System.out.println("        },");
			System.out.println("        \"output\": {");
			System.out.println("            \"serverPublicKey\": \"" + BaseEncoding.base64().encode(kcu.convertPublicKeyToBytes(serverPublicKey)) + "\"");
			System.out.println("        }");
			if (i == max - 1) {
				System.out.println("    }");
			} else {
				System.out.println("    },");
			}
			
			PublicKey serverPublicDecrypted = activationClient.decryptServerPublicKey(cServerPublicKey, devicePrivateKey, ephemeralPublicKey, activationOTP, activationIdShort, activationNonce);
			assertEquals(serverPublicKey, serverPublicDecrypted);
		}
		
		System.out.println("]");
		System.out.println("[");
		
		for (int i = 0; i < max; i++) {
			
			activationIdShort = new IdentifierGenerator().generateActivationIdShort();
			activationOTP = new IdentifierGenerator().generateActivationOTP();
			activationNonce = activationServer.generateActivationNonce();
			
			KeyPair kp = activationClient.generateDeviceKeyPair();
			devicePrivateKey = kp.getPrivate();
			devicePublicKey = kp.getPublic();
			
			kp = activationServer.generateServerKeyPair();
			serverPrivateKey = kp.getPrivate();
			serverPublicKey = kp.getPublic();
			
			kp = activationServer.generateServerKeyPair();
			ephemeralPrivateKey = kp.getPrivate();
			ephemeralPublicKey = kp.getPublic();
			
			kp = activationServer.generateServerKeyPair();
			PrivateKey masterPrivateKey = kp.getPrivate();
			PublicKey masterPublicKey = kp.getPublic();
			
			cServerPublicKey = activationServer.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOTP, activationIdShort, activationNonce);
			byte[] cServerPublicKeySignature = activationServer.computeServerPublicKeySignature(cServerPublicKey, masterPrivateKey);
			
			KeyConversionUtils kcu = new KeyConversionUtils();
			
			System.out.println("    {");			
			System.out.println("        \"input\": {");
			System.out.println("            \"encryptedServerPublicKey\": \"" + BaseEncoding.base64().encode(cServerPublicKey) + "\",");
			System.out.println("            \"masterServerPrivateKey\": \"" + BaseEncoding.base64().encode(kcu.convertPrivateKeyToBytes(masterPrivateKey)) + "\",");
			System.out.println("            \"masterServerPublicKey\": \"" + BaseEncoding.base64().encode(kcu.convertPublicKeyToBytes(masterPublicKey)) + "\"");
			System.out.println("        },");
			System.out.println("        \"output\": {");
			System.out.println("            \"encryptedServerPublicKeySignature\": \"" + BaseEncoding.base64().encode(cServerPublicKeySignature) + "\"");
			System.out.println("        }");
			if (i == max - 1) {
				System.out.println("    }");
			} else {
				System.out.println("    },");
			}
			
		}
		
		System.out.println("]");
	}

}
