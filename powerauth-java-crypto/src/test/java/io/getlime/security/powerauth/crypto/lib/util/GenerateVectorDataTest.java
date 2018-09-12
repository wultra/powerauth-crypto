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

package io.getlime.security.powerauth.crypto.lib.util;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;

/**
 * Generate test vectors
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class GenerateVectorDataTest {

	/**
	 * Register crypto providers
	 */
	@Before
	public void setUp() {
		// Add Bouncy Castle Security Provider
		Security.addProvider(new BouncyCastleProvider());
		PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());
	}

	/**
	 * Generate test data for activation data signature.
	 * @throws Exception In case any unknown error occurs.
	 */
	@Test
	public void testVerifyActivationDataV2() throws Exception {
		String activationOTP;
		String activationIdShort;

		PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

		System.out.println("## Verify Activation Data Signature (V2)");
		System.out.println("[");

		CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

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
			System.out.println("            \"masterPrivateKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(masterPrivateKey)) + "\",");
			System.out.println("            \"masterPublicKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(masterPublicKey)) + "\"");
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

	/**
	 * Generate test data for activation data signature.
	 * @throws Exception In case any unknown error occurs.
	 */
	@Test
	public void testVerifyActivationDataV3() throws Exception {
		String activationCode;

		PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

		System.out.println("## Verify Activation Data Signature (V3)");
		System.out.println("[");

		CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
		IdentifierGenerator identifierGenerator = new IdentifierGenerator();

		int max = 20;
		for (int i = 0; i < max; i++) {
			activationCode = identifierGenerator.generateActivationCode();

			KeyPair kp = activationServer.generateServerKeyPair();
			PrivateKey masterPrivateKey = kp.getPrivate();
			PublicKey masterPublicKey = kp.getPublic();

			byte[] activationSignature = activationServer.generateActivationSignature(activationCode, masterPrivateKey);

			System.out.println("    {");
			System.out.println("        \"input\": {");
			System.out.println("            \"activationCode\": \"" + activationCode + "\",");
			System.out.println("            \"masterPrivateKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(masterPrivateKey)) + "\",");
			System.out.println("            \"masterPublicKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(masterPublicKey)) + "\"");
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

	/**
	 * Generate test data for public key encryption.
	 * @throws Exception In case any unknown error occurs.
	 */
	@Test
	public void testEncryptDevicePublicKey() throws Exception {
		PowerAuthClientActivation activation = new PowerAuthClientActivation();

		CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

		System.out.println("## Encrypt Device Public Key");
		System.out.println("[");

		KeyPair masterKeyPair = new KeyGenerator().generateKeyPair();

		int max = 20;
		for (int i = 0; i < max; i++) {
			String activationOTP = new IdentifierGenerator().generateActivationIdShort();
			String activationIdShort = new IdentifierGenerator().generateActivationOTP();
			byte[] activationNonce = activation.generateActivationNonce();
			PublicKey publicKey = new KeyGenerator().generateKeyPair().getPublic();
			byte[] applicationKey = new KeyGenerator().generateRandomBytes(16);
			byte[] applicationSecret = new KeyGenerator().generateRandomBytes(16);

			KeyPair ephemeralKeyPair = new KeyGenerator().generateKeyPair();

			byte[] cDevicePublicKey = activation.encryptDevicePublicKey(publicKey, ephemeralKeyPair.getPrivate(), masterKeyPair.getPublic(), activationOTP, activationIdShort, activationNonce);
			byte[] applicationSignature = activation.computeApplicationSignature(activationIdShort, activationNonce, cDevicePublicKey, applicationKey, applicationSecret);

			System.out.println("    {");
			System.out.println("        \"input\": {");
			System.out.println("            \"activationIdShort\": \"" + activationIdShort + "\",");
			System.out.println("            \"activationOtp\": \"" + activationOTP + "\",");
			System.out.println("            \"activationNonce\": \"" + BaseEncoding.base64().encode(activationNonce) + "\",");
			System.out.println("            \"masterPublicKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(masterKeyPair.getPublic())) + "\",");
			System.out.println("            \"ephemeralPrivateKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(ephemeralKeyPair.getPrivate())) + "\",");
			System.out.println("            \"applicationKey\": \"" + BaseEncoding.base64().encode(applicationKey) + "\",");
			System.out.println("            \"applicationSecret\": \"" + BaseEncoding.base64().encode(applicationSecret) + "\",");
			System.out.println("            \"devicePublicKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(publicKey)) + "\"");
			System.out.println("        },");
			System.out.println("        \"output\": {");
			System.out.println("            \"cDevicePublicKey\": \"" + BaseEncoding.base64().encode(cDevicePublicKey) + "\",");
			System.out.println("            \"applicationSignature\": \"" + BaseEncoding.base64().encode(applicationSignature) + "\"");
			System.out.println("        }");
			if (i == max - 1) {
				System.out.println("    }");
			} else {
				System.out.println("    },");
			}
		}

		System.out.println("]");
	}

	/**
	 * Generate test data for master key derivation.
	 * @throws Exception In case any unknown error occurs.
	 */
	@Test
	public void testMasterKeyDerivation() throws Exception {

		PowerAuthClientActivation activationClient = new PowerAuthClientActivation();
		PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

		CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

		System.out.println("## Deduce Master Secret Key");
		System.out.println("[");

		int max = 20;
		for (int i = 0; i < max; i++) {
			KeyPair deviceKeyPair = activationClient.generateDeviceKeyPair();
			KeyPair serverKeyPair = activationServer.generateServerKeyPair();
			SecretKey masterSecretKey = new KeyGenerator().computeSharedKey(deviceKeyPair.getPrivate(), serverKeyPair.getPublic());

			System.out.println("    {");
			System.out.println("        \"input\": {");
			System.out.println("            \"devicePrivateKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(deviceKeyPair.getPrivate())) + "\",");
			System.out.println("            \"devicePublicKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(deviceKeyPair.getPublic())) + "\",");
			System.out.println("            \"serverPrivateKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(serverKeyPair.getPrivate())) + "\",");
			System.out.println("            \"serverPublicKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(serverKeyPair.getPublic())) + "\"");
			System.out.println("        },");
			System.out.println("        \"output\": {");
			System.out.println("            \"masterSecretKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(masterSecretKey)) + "\"");
			System.out.println("        }");
			if (i == max - 1) {
				System.out.println("    }");
			} else {
				System.out.println("    },");
			}
		}

		System.out.println("]");

	}

	/**
	 * Generate test data for key derivation.
	 * @throws Exception In case any unknown error occurs.
	 */
	@Test
	public void testDerivedKeyDerivation() throws Exception {

		PowerAuthClientActivation activationClient = new PowerAuthClientActivation();
		PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

		CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

		System.out.println("## Derive Keys From Master Secret");
		System.out.println("[");

		int max = 20;

		for (int i = 0; i < max; i++) {
			KeyPair deviceKeyPair = activationClient.generateDeviceKeyPair();
			KeyPair serverKeyPair = activationServer.generateServerKeyPair();
			SecretKey masterSecretKey = new KeyGenerator().computeSharedKey(deviceKeyPair.getPrivate(), serverKeyPair.getPublic());

			PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();

			System.out.println("    {");
			System.out.println("        \"input\": {");
			System.out.println("            \"masterSecretKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(masterSecretKey)) + "\"");
			System.out.println("        },");
			System.out.println("        \"output\": {");
			System.out.println("            \"signaturePossessionKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(keyFactory.generateClientSignaturePossessionKey(masterSecretKey))) + "\",");
			System.out.println("            \"signatureKnowledgeKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(keyFactory.generateClientSignatureKnowledgeKey(masterSecretKey))) + "\",");
			System.out.println("            \"signatureBiometryKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(keyFactory.generateClientSignatureBiometryKey(masterSecretKey))) + "\",");
			System.out.println("            \"transportKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(keyFactory.generateServerTransportKey(masterSecretKey))) + "\",");
			System.out.println("            \"vaultEncryptionKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(keyFactory.generateServerEncryptedVaultKey(masterSecretKey))) + "\"");
			System.out.println("        }");
			if (i == max - 1) {
				System.out.println("    }");
			} else {
				System.out.println("    },");
			}
		}

		System.out.println("]");
	}

	/**
	 * Generate test data for decrypting server public key.
	 * @throws Exception In case any unknown error occurs.
	 */
	@Test
	public void testActivationAccept() throws Exception {
		String activationOTP;
		String activationIdShort;
		byte[] activationNonce;
		PublicKey serverPublicKey;
		byte[] cServerPublicKey;

		PublicKey devicePublicKey;
		PrivateKey devicePrivateKey;

		PublicKey ephemeralPublicKey;
		PrivateKey ephemeralPrivateKey;

		PowerAuthServerActivation activationServer = new PowerAuthServerActivation();
		PowerAuthClientActivation activationClient = new PowerAuthClientActivation();

		System.out.println("### Decrypt Server Public Key");
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
			serverPublicKey = kp.getPublic();

			kp = activationServer.generateServerKeyPair();
			ephemeralPrivateKey = kp.getPrivate();
			ephemeralPublicKey = kp.getPublic();

			cServerPublicKey = activationServer.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOTP, activationIdShort, activationNonce);
			CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

			System.out.println("    {");
			System.out.println("        \"input\": {");
			System.out.println("            \"activationIdShort\": \"" + activationIdShort + "\",");
			System.out.println("            \"activationOtp\": \"" + activationOTP + "\",");
			System.out.println("            \"activationNonce\": \"" + BaseEncoding.base64().encode(activationNonce) + "\",");
			System.out.println("            \"devicePrivateKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(devicePrivateKey)) + "\",");
			System.out.println("            \"devicePublicKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(devicePublicKey)) + "\",");
			System.out.println("            \"encryptedServerPublicKey\": \"" + BaseEncoding.base64().encode(cServerPublicKey) + "\",");
			System.out.println("            \"ephemeralPublicKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(ephemeralPublicKey)) + "\"");
			System.out.println("        },");
			System.out.println("        \"output\": {");
			System.out.println("            \"serverPublicKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(serverPublicKey)) + "\"");
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
	}

	/**
	 * Generate test data for verifying server response data.
	 * @throws Exception In case any unknown error occurs.
	 */
	@Test
	public void testVerifyServerPublicKeySignature() throws Exception {
		String activationId;
		String activationOTP;
		String activationIdShort;
		byte[] activationNonce;
		PublicKey serverPublicKey;
		byte[] cServerPublicKey;
		PublicKey devicePublicKey;
		PrivateKey ephemeralPrivateKey;

		PowerAuthServerActivation activationServer = new PowerAuthServerActivation();
		PowerAuthClientActivation activationClient = new PowerAuthClientActivation();

		System.out.println("### Verify Encrypted Server Public Key Signature");
		System.out.println("[");

		int max = 20;
		for (int i = 0; i < max; i++) {

			activationId = new IdentifierGenerator().generateActivationId();
			activationIdShort = new IdentifierGenerator().generateActivationIdShort();
			activationOTP = new IdentifierGenerator().generateActivationOTP();
			activationNonce = activationServer.generateActivationNonce();

			KeyPair kp = activationClient.generateDeviceKeyPair();
			devicePublicKey = kp.getPublic();

			kp = activationServer.generateServerKeyPair();
			serverPublicKey = kp.getPublic();

			kp = activationServer.generateServerKeyPair();
			ephemeralPrivateKey = kp.getPrivate();

			kp = activationServer.generateServerKeyPair();
			PrivateKey masterPrivateKey = kp.getPrivate();
			PublicKey masterPublicKey = kp.getPublic();

			cServerPublicKey = activationServer.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOTP, activationIdShort, activationNonce);
			byte[] cServerPublicKeySignature = activationServer.computeServerDataSignature(activationId, cServerPublicKey, masterPrivateKey);

			CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

			System.out.println("    {");
			System.out.println("        \"input\": {");
			System.out.println("            \"activationId\": \"" + activationId + "\",");
			System.out.println("            \"encryptedServerPublicKey\": \"" + BaseEncoding.base64().encode(cServerPublicKey) + "\",");
			System.out.println("            \"masterServerPrivateKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(masterPrivateKey)) + "\",");
			System.out.println("            \"masterServerPublicKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(masterPublicKey)) + "\"");
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

	/**
	 * Generate test data for signature validation
	 * @throws Exception In case any unknown error occurs.
	 */
	@Test
	public void testSignatureValidation() throws Exception {

		System.out.println("### Signature Validation");
		System.out.println("[");

		int max = 5;
		int key_max = 2;
		int ctr_max = 10;
		int data_max = 256;
		for (int j = 0; j < max; j++) {

			// Prepare data
			KeyGenerator keyGenerator = new KeyGenerator();
			CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

			KeyPair serverKeyPair = keyGenerator.generateKeyPair();
			PublicKey serverPublicKey = serverKeyPair.getPublic();

			KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
			PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();

			PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
			PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();

			for (int i = 0; i < key_max; i++) {

				// compute data signature
				SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
				SecretKey signaturePossessionKey = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
				SecretKey signatureKnowledgeKey = clientKeyFactory.generateClientSignatureKnowledgeKey(masterClientKey);
				SecretKey signatureBiometryKey = clientKeyFactory.generateClientSignatureBiometryKey(masterClientKey);

				for (int ctr = 0; ctr < ctr_max; ctr++) {

					// generate random data
					byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * data_max));

					String signature = clientSignature.signatureForData(data, Collections.singletonList(signaturePossessionKey), ctr);
					String signatureType = "possession";

					System.out.println("    {");
					System.out.println("        \"input\": {");
					System.out.println("            \"signaturePossessionKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)) + "\",");
					System.out.println("            \"signatureKnowledgeKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)) + "\",");
					System.out.println("            \"signatureBiometryKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)) + "\",");
					System.out.println("            \"signatureType\": \"" + signatureType + "\",");
					System.out.println("            \"counter\": \"" + ctr + "\",");
					System.out.println("            \"data\": \"" + BaseEncoding.base64().encode(data) + "\"");
					System.out.println("        },");
					System.out.println("        \"output\": {");
					System.out.println("            \"signature\": \"" + signature + "\"");
					System.out.println("        }");
					System.out.println("    },");
				}

				for (int ctr = 0; ctr < ctr_max; ctr++) {

					// generate random data
					byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * data_max));

					String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey, signatureKnowledgeKey), ctr);
					String signatureType = "possession_knowledge";

					System.out.println("    {");
					System.out.println("        \"input\": {");
					System.out.println("            \"signaturePossessionKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)) + "\",");
					System.out.println("            \"signatureKnowledgeKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)) + "\",");
					System.out.println("            \"signatureBiometryKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)) + "\",");
					System.out.println("            \"signatureType\": \"" + signatureType + "\",");
					System.out.println("            \"counter\": \"" + ctr + "\",");
					System.out.println("            \"data\": \"" + BaseEncoding.base64().encode(data) + "\"");
					System.out.println("        },");
					System.out.println("        \"output\": {");
					System.out.println("            \"signature\": \"" + signature + "\"");
					System.out.println("        }");
					System.out.println("    },");

				}

				for (int ctr = 0; ctr < ctr_max; ctr++) {

					// generate random data
					byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * data_max));

					String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), ctr);
					String signatureType = "possession_knowledge_biometry";

					System.out.println("    {");
					System.out.println("        \"input\": {");
					System.out.println("            \"signaturePossessionKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)) + "\",");
					System.out.println("            \"signatureKnowledgeKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)) + "\",");
					System.out.println("            \"signatureBiometryKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)) + "\",");
					System.out.println("            \"signatureType\": \"" + signatureType + "\",");
					System.out.println("            \"counter\": \"" + ctr + "\",");
					System.out.println("            \"data\": \"" + BaseEncoding.base64().encode(data) + "\"");
					System.out.println("        },");
					System.out.println("        \"output\": {");
					System.out.println("            \"signature\": \"" + signature + "\"");
					System.out.println("        }");
					if (ctr == ctr_max - 1 && i == key_max - 1 && j == max - 1) {
						System.out.println("    }");
					} else {
						System.out.println("    },");
					}

				}
			}
		}
		System.out.println("]");
	}

    @Test
    public void testPublicKeyFingerprint() throws Exception {

        PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

        System.out.println("## Public Key Fingerprint");
        System.out.println("[");

        CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

        int max = 100;
        for (int i = 0; i < max; i++) {
            KeyPair kp = activationServer.generateServerKeyPair();
            ECPublicKey publicKey = (ECPublicKey) kp.getPublic();

            final String fingerprint = ECPublicKeyFingerprint.compute(publicKey);

            // Replicate the key normalization for the testing purposes.
            final BigInteger x = publicKey.getW().getAffineX();
            byte[] devicePublicKeyBytes = x.toByteArray();
            if (devicePublicKeyBytes[0] == 0x00) {
                devicePublicKeyBytes = Arrays.copyOfRange(devicePublicKeyBytes, 1, 33);
            }

            System.out.println("    {");
            System.out.println("        \"input\": {");
            System.out.println("            \"publicKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(publicKey)) + "\"");
            System.out.println("        },");
            System.out.println("        \"output\": {");
            System.out.println("            \"publicKeyCoordX\": \"" + BaseEncoding.base64().encode(devicePublicKeyBytes) + "\",");
            System.out.println("            \"fingerprint\": \"" + fingerprint + "\"");
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
