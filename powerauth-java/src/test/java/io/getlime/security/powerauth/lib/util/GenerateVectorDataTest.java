package io.getlime.security.powerauth.lib.util;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.SecretKey;

import io.getlime.security.powerauth.lib.provider.CryptoProviderUtilFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import com.google.common.io.BaseEncoding;

import io.getlime.security.powerauth.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.server.activation.PowerAuthServerActivation;

/**
 * Generate test vectors
 * 
 * @author Petr Dvorak
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
	public void testVerifyActivationData() throws Exception {
		String activationOTP;
		String activationIdShort;

		PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

		System.out.println("## Verify Activation Data Signature");
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
	 * Generate test data for public key encryption. 
	 * @throws Exception In case any unknown error occurs.
	 */
	@Test
	public void testEncryptDevicePublicKey() throws Exception {
		PowerAuthClientActivation activation = new PowerAuthClientActivation();
		
		CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

		System.out.println("## Encrypt Device Public Key");
		System.out.println("[");

		int max = 20;
		for (int i = 0; i < max; i++) {
			String activationOTP = new IdentifierGenerator().generateActivationIdShort();
			String activationIdShort = new IdentifierGenerator().generateActivationOTP();
			byte[] activationNonce = activation.generateActivationNonce();
			PublicKey publicKey = new KeyGenerator().generateKeyPair().getPublic();
			byte[] applicationKey = new KeyGenerator().generateRandomBytes(16);
			byte[] applicationSecret = new KeyGenerator().generateRandomBytes(16);

			byte[] cDevicePublicKey = activation.encryptDevicePublicKey(publicKey, activationOTP, activationIdShort, activationNonce);
			byte[] applicationSignature = activation.computeApplicationSignature(activationIdShort, activationNonce, cDevicePublicKey, applicationKey, applicationSecret);

			System.out.println("    {");
			System.out.println("        \"input\": {");
			System.out.println("            \"activationIdShort\": \"" + activationIdShort + "\",");
			System.out.println("            \"activationOtp\": \"" + activationOTP + "\",");
			System.out.println("            \"activationNonce\": \"" + BaseEncoding.base64().encode(activationNonce) + "\",");
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
			System.out.println("            \"serverePrivateKey\": \"" + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(serverKeyPair.getPrivate())) + "\",");
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
		String activationOTP = null;
		String activationIdShort = null;
		byte[] activationNonce = null;
		PublicKey serverPublicKey = null;
		byte[] cServerPublicKey = null;

		PublicKey devicePublicKey = null;
		PrivateKey devicePrivateKey = null;

		PublicKey ephemeralPublicKey = null;
		PrivateKey ephemeralPrivateKey = null;

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
		String activationId = null;
		String activationOTP = null;
		String activationIdShort = null;
		byte[] activationNonce = null;
		PublicKey serverPublicKey = null;
		byte[] cServerPublicKey = null;
		PublicKey devicePublicKey = null;
		PrivateKey ephemeralPrivateKey = null;

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

					String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey), ctr);
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

}
