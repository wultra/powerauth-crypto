package io.getlime.security.client.app;

import java.io.Console;
import java.io.FileWriter;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.common.io.BaseEncoding;

import io.getlime.rest.api.model.ActivationCreateRequest;
import io.getlime.rest.api.model.ActivationCreateResponse;
import io.getlime.rest.api.model.ActivationRemoveRequest;
import io.getlime.rest.api.model.ActivationRemoveResponse;
import io.getlime.rest.api.model.ActivationStatusRequest;
import io.getlime.rest.api.model.ActivationStatusResponse;
import io.getlime.rest.api.model.PowerAuthAPIRequest;
import io.getlime.rest.api.model.PowerAuthAPIResponse;
import io.getlime.security.powerauth.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpHeader;

@SpringBootApplication
public class Application implements CommandLineRunner {

	private static final String expectedApplicationId = "a1c97807-795a-466e-87bf-230d8ac1451e";
	private static final String expectedApplicationSecret = "d358e78a-8d12-4595-bf69-6eff2c2afc04";
	private JSONObject clientConfigObject = null;

	private String getApplicationId() {
		if (clientConfigObject.get("applicationId") != null) {
			return (String) clientConfigObject.get("applicationId");
		} else {
			return expectedApplicationId;
		}
	}

	private String getApplicationSecret() {
		if (clientConfigObject.get("applicationSecret") != null) {
			return (String) clientConfigObject.get("applicationSecret");
		} else {
			return expectedApplicationSecret;
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@SuppressWarnings("unchecked")
	@Override
	public void run(String... args) throws Exception {

		// Add Bouncy Castle Security Provider
		Security.addProvider(new BouncyCastleProvider());

		// Options definition
		Options options = new Options();
		options.addOption("h", "help", false, "Print this help manual");
		options.addOption("u", "url", true, "Base URL of the PowerAuth 2.0 Standard RESTful API");
		options.addOption("m", "method", true, "What API method to call, available names are 'prepare', 'status', 'remove', 'sign' and 'unlock'");
		options.addOption("c", "config-file", true, "Specifies a path to the config file with Base64 encoded server master public key, application ID and application secret");
		options.addOption("s", "status-file", true, "Path to the file with the activation status, serving as the data persistence.");
		options.addOption("a", "activation-code", true, "In case a specified method is 'prepare', this field contains the activation key (a concatenation of a short activation ID and activation OTP)");
		options.addOption("h", "http-method", true, "In case a specified method is 'sign', this field specifies a HTTP method, as specified in PowerAuth signature process.");
		options.addOption("e", "endpoint", true, "In case a specified method is 'sign', this field specifies a URI identifier, as specified in PowerAuth signature process.");
		options.addOption("l", "signature-type", true, "In case a specified method is 'sign', this field specifies a signature type, as specified in PowerAuth signature process.");
		options.addOption("d", "data-file", true, "In case a specified method is 'sign', this field specifies a file with the input data to be signed and verified with the server, as specified in PowerAuth signature process.");

		// Options parsing
		CommandLineParser parser = new DefaultParser();
		CommandLine cmd = parser.parse(options, args);

		// Check if help was invoked
		if (cmd.hasOption("h")) {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp("java -jar powerauth-java-client-app.jar", options);
			return;
		}

		// Prepare converters
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
		MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter(mapper);
		List<HttpMessageConverter<?>> converters = new ArrayList<>();
		converters.add(converter);

		// Prepare the REST template
		RestTemplate template = new RestTemplate();
		template.setMessageConverters(converters);

		// Prepare PowerAuth 2.0 related client components and utility
		// components
		KeyConversionUtils keyConversion = new KeyConversionUtils();
		KeyGenerator keyGenerator = new KeyGenerator();
		PowerAuthClientSignature signature = new PowerAuthClientSignature();
		PowerAuthClientVault vault = new PowerAuthClientVault();
		PowerAuthClientActivation activation = new PowerAuthClientActivation();
		PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();

		// Read values
		String statusFileName = cmd.getOptionValue("s");
		String method = cmd.getOptionValue("m");
		String uriString = cmd.getOptionValue("u");
		String configFileName = cmd.getOptionValue("c");

		// Read master public key
		PublicKey masterPublicKey = null;
		if (Files.exists(Paths.get(configFileName))) {
			byte[] statusFileBytes = Files.readAllBytes(Paths.get(configFileName));
			clientConfigObject = (JSONObject) JSONValue.parse(new String(statusFileBytes));
			byte[] masterKeyBytes = BaseEncoding.base64().decode((String) clientConfigObject.get("masterPublicKey"));
			masterPublicKey = keyConversion.convertBytesToPublicKey(masterKeyBytes);
		} else {
			System.out.println("Unable to read client config file");
			System.out.println();
			System.out.println("### Failed.");
			System.out.println();
		}

		// Read current activation state from the activation state file or
		// create an empty state
		JSONObject resultStatusObject = null;
		if (Files.exists(Paths.get(statusFileName))) {
			byte[] statusFileBytes = Files.readAllBytes(Paths.get(statusFileName));
			resultStatusObject = (JSONObject) JSONValue.parse(new String(statusFileBytes));
		} else {
			resultStatusObject = new JSONObject();
		}

		// Execute the code for given methods
		if (method.equals("prepare")) {

			System.out.println("### PowerAuth 2.0 Client Activation Started");
			System.out.println();

			// Prepare the activation URI
			String fullURIString = uriString + "/pa/activation/create";
			URI uri = new URI(fullURIString);

			// Fetch and parse the activation code
			String activationCode = cmd.getOptionValue("a");
			String activationIdShort = activationCode.substring(0, 11);
			String activationOTP = activationCode.substring(12, 23);

			System.out.println("Activation ID Short: " + activationIdShort);
			System.out.println("Activation OTP: " + activationOTP);

			// Generate device key pair and encrypt the device public key
			KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
			byte[] nonceDeviceBytes = activation.generateActivationNonce();
			byte[] cDevicePublicKeyBytes = activation.encryptDevicePublicKey(deviceKeyPair.getPublic(), activationOTP, activationIdShort, nonceDeviceBytes);

			// Prepare the server request
			ActivationCreateRequest requestObject = new ActivationCreateRequest();
			requestObject.setActivationIdShort(activationIdShort);
			requestObject.setActivationName("PowerAuth 2.0 Reference Client");
			requestObject.setActivationNonce(BaseEncoding.base64().encode(nonceDeviceBytes));
			requestObject.setcDevicePublicKey(BaseEncoding.base64().encode(cDevicePublicKeyBytes));
			PowerAuthAPIRequest<ActivationCreateRequest> body = new PowerAuthAPIRequest<>();
			body.setRequestObject(requestObject);
			RequestEntity<PowerAuthAPIRequest<ActivationCreateRequest>> request = new RequestEntity<PowerAuthAPIRequest<ActivationCreateRequest>>(body, HttpMethod.POST, uri);

			// Call the server with activation data
			System.out.println("Calling PowerAuth 2.0 Standard RESTful API at " + fullURIString + " ...");
			try {
				ResponseEntity<PowerAuthAPIResponse<ActivationCreateResponse>> response = template.exchange(request, new ParameterizedTypeReference<PowerAuthAPIResponse<ActivationCreateResponse>>() {
				});
				System.out.println("Done.");
				System.out.println();

				// Process the server response
				ActivationCreateResponse responseObject = response.getBody().getResponseObject();
				String activationId = responseObject.getActivationId();
				byte[] nonceServerBytes = BaseEncoding.base64().decode(responseObject.getActivationNonce());
				byte[] cServerPubKeyBytes = BaseEncoding.base64().decode(responseObject.getcServerPublicKey());
				byte[] cServerPubKeySignatureBytes = BaseEncoding.base64().decode(responseObject.getcServerPublicKeySignature());
				byte[] ephemeralKeyBytes = BaseEncoding.base64().decode(responseObject.getEphemeralPublicKey());
				PublicKey ephemeralPublicKey = keyConversion.convertBytesToPublicKey(ephemeralKeyBytes);

				// Verify that the server public key signature is valid
				boolean isDataSignatureValid = activation.verifyServerPublicKeySignature(cServerPubKeyBytes, cServerPubKeySignatureBytes, masterPublicKey);

				if (isDataSignatureValid) {

					// Decrypt the server public key
					PublicKey serverPublicKey = activation.decryptServerPublicKey(cServerPubKeyBytes, deviceKeyPair.getPrivate(), ephemeralPublicKey, activationOTP, activationIdShort, nonceServerBytes);

					// Compute master secret key
					SecretKey masterSecretKey = keyFactory.generateClientMasterSecretKey(deviceKeyPair.getPrivate(), serverPublicKey);

					// Derive PowerAuth keys from master secret key
					SecretKey signaturePossessionSecretKey = keyFactory.generateClientSignaturePossessionKey(masterSecretKey);
					SecretKey signatureKnoweldgeSecretKey = keyFactory.generateClientSignatureKnowledgeKey(masterSecretKey);
					SecretKey signatureBiometrySecretKey = keyFactory.generateClientSignatureBiometryKey(masterSecretKey);
					SecretKey transportMasterKey = keyFactory.generateServerTransportKey(masterSecretKey);
					// DO NOT EVER STORE ...
					SecretKey vaultUnlockMasterKey = keyFactory.generateServerEncryptedVaultKey(masterSecretKey);

					// Encrypt the original device private key using the vault
					// unlock key
					byte[] encryptedDevicePrivateKey = vault.encryptDevicePrivateKey(deviceKeyPair.getPrivate(), vaultUnlockMasterKey);

					byte[] salt = keyGenerator.generateRandomBytes(16);
					Console console = System.console();
					char[] password = console.readPassword("Select a password to encrypt the knowledge related key: ");
					byte[] cSignatureKnoweldgeSecretKey = this.storeSignatureKnowledgeKey(password, signatureKnoweldgeSecretKey, salt, keyGenerator);

					// Prepare the status object to be stored
					resultStatusObject.put("activationId", activationId);
					resultStatusObject.put("clientPublicKey", BaseEncoding.base64().encode(keyConversion.convertPublicKeyToBytes(deviceKeyPair.getPublic())));
					resultStatusObject.put("encryptedDevicePrivateKey", BaseEncoding.base64().encode(encryptedDevicePrivateKey));
					resultStatusObject.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(signaturePossessionSecretKey)));
					resultStatusObject.put("signatureKnowledgeKeyEncrypted", BaseEncoding.base64().encode(cSignatureKnoweldgeSecretKey));
					resultStatusObject.put("signatureKnowledgeKeySalt", BaseEncoding.base64().encode(salt));
					resultStatusObject.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(signatureBiometrySecretKey)));
					resultStatusObject.put("transportMasterKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(transportMasterKey)));
					resultStatusObject.put("counter", new Long(0));

					// Store the resulting status
					String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(resultStatusObject);
					try (FileWriter file = new FileWriter(statusFileName)) {
						file.write(formatted);
					}
					System.out.println("Activation ID: " + activationId);
					System.out.println("Activation data were stored in file: " + statusFileName);
					System.out.println("Activation data file contents: " + formatted);
					System.out.println();

					// Show the device fingerprint for the visual control data
					// was
					// received correctly on the server
					System.out.println("Check the device public key fingerprint: " + activation.computeDevicePublicKeyFingerprint(deviceKeyPair.getPublic()));
					System.out.println();
					System.out.println("### Done.");
					System.out.println();

				} else {
					System.out.println("Activation data signature does not match. Either someone tried to spoof your connection, or your device master key is invalid.");
					System.out.println();
					System.out.println("### Failed.");
					System.out.println();
				}
			} catch (HttpClientErrorException exception) {
				String responseString = exception.getResponseBodyAsString();
				try {
					Map<String, Object> errorMap = mapper.readValue(responseString, Map.class);
					System.out.println(((Map<String, Object>) errorMap.get("error")).get("message"));
				} catch (Exception e) {
					System.out.println("Service error - HTTP " + exception.getStatusCode().toString() + ": " + exception.getStatusText());
				}
				System.out.println();
				System.out.println("### Failed.");
				System.out.println();
			} catch (ResourceAccessException exception) {
				System.out.println("Connection error - connection refused");
				System.out.println();
				System.out.println("### Failed.");
				System.out.println();
			} catch (Exception exception) {
				System.out.println("Unknown error - " + exception.getLocalizedMessage());
				System.out.println();
				System.out.println("### Failed.");
				System.out.println();
			}

		} else if (method.equals("status")) {

			System.out.println("### PowerAuth 2.0 Client Activation Status Check Started");
			System.out.println();

			// Prepare the activation URI
			String fullURIString = uriString + "/pa/activation/status";
			URI uri = new URI(fullURIString);

			// Get data from status
			String activationId = (String) resultStatusObject.get("activationId");
			String transportMasterKeyBase64 = (String) resultStatusObject.get("transportMasterKey");
			SecretKey transportMasterKey = keyConversion.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(transportMasterKeyBase64));

			// Send the activation status request to the server
			ActivationStatusRequest requestObject = new ActivationStatusRequest();
			requestObject.setActivationId(activationId);
			PowerAuthAPIRequest<ActivationStatusRequest> body = new PowerAuthAPIRequest<>();
			body.setRequestObject(requestObject);
			RequestEntity<PowerAuthAPIRequest<ActivationStatusRequest>> request = new RequestEntity<PowerAuthAPIRequest<ActivationStatusRequest>>(body, HttpMethod.POST, uri);

			// Call the server with activation data
			System.out.println("Calling PowerAuth 2.0 Standard RESTful API at " + fullURIString + " ...");
			try {
				ResponseEntity<PowerAuthAPIResponse<ActivationStatusResponse>> response = template.exchange(request, new ParameterizedTypeReference<PowerAuthAPIResponse<ActivationStatusResponse>>() {
				});
				System.out.println("Done.");
				System.out.println();

				// Process the server response
				ActivationStatusResponse responseObject = response.getBody().getResponseObject();
				String activationIdResponse = responseObject.getActivationId();
				byte[] cStatusBlob = BaseEncoding.base64().decode(responseObject.getcStatusBlob());

				// Print the results
				ActivationStatusBlobInfo statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, transportMasterKey);
				System.out.println("Activation ID: " + activationId);
				System.out.println("Server Activation ID: " + activationIdResponse);
				System.out.println("Valid: " + statusBlob.isValid());
				System.out.println("Status: " + statusBlob.getActivationStatus());
				System.out.println("Counter: " + statusBlob.getCounter());
				System.out.println("Failures: " + statusBlob.getFailedAttempts());
				System.out.println("### Done.");
				System.out.println();
			} catch (HttpClientErrorException exception) {
				String responseString = exception.getResponseBodyAsString();
				try {
					Map<String, Object> errorMap = mapper.readValue(responseString, Map.class);
					System.out.println(((Map<String, Object>) errorMap.get("error")).get("message"));
				} catch (Exception e) {
					System.out.println("Service error - HTTP " + exception.getStatusCode().toString() + ": " + exception.getStatusText());
				}
				System.out.println();
				System.out.println("### Failed.");
				System.out.println();
			} catch (ResourceAccessException exception) {
				System.out.println("Connection error - connection refused");
				System.out.println();
				System.out.println("### Failed.");
				System.out.println();
			} catch (Exception exception) {
				System.out.println("Unknown error - " + exception.getLocalizedMessage());
				System.out.println();
				System.out.println("### Failed.");
				System.out.println();
			}

		} else if (method.equals("remove")) {

			System.out.println("### PowerAuth 2.0 Client Activation Removal Started");
			System.out.println();

			// Prepare the activation URI
			String fullURIString = uriString + "/pa/activation/remove";
			URI uri = new URI(fullURIString);

			// Get data from status
			String activationId = (String) resultStatusObject.get("activationId");
			long counter = (long) resultStatusObject.get("counter");
			byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signaturePossessionKey"));
			byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureKnowledgeKeySalt"));
			byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureKnowledgeKeyEncrypted"));

			// Ask for the password to unlock knowledge factor key
			Console console = System.console();
			char[] password = console.readPassword("Enter your password to unlock the knowledge related key: ");

			// Get the signature keys
			SecretKey signaturePossessionKey = keyConversion.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
			SecretKey signatureKnowledgeKey = this.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);

			// Generate nonce
			String pa_nonce = BaseEncoding.base64().encode(keyGenerator.generateRandomBytes(16));

			// Compute the current PowerAuth 2.0 signature for possession and
			// knowledge factor
			String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/activation/remove", getApplicationSecret(), pa_nonce, null);
			String pa_signature = signature.signatureForData(signatureBaseString.getBytes("UTF-8"), Arrays.asList(signaturePossessionKey, signatureKnowledgeKey), counter);
			String httpAuhtorizationHeader = PowerAuthHttpHeader.getPowerAuthSignatureHTTPHeader(activationId, getApplicationId(), pa_nonce, PowerAuthConstants.SIGNATURE_TYPES.POSSESSION_KNOWLEDGE, pa_signature, "2.0");
			System.out.println("Coomputed X-PowerAuth-Authorization header: " + httpAuhtorizationHeader);
			System.out.println();

			// Increment the counter
			counter += 1;
			resultStatusObject.put("counter", new Long(counter));

			// Store the activation status (updated counter)
			String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(resultStatusObject);
			try (FileWriter file = new FileWriter(statusFileName)) {
				file.write(formatted);
			}

			// Prepare HTTP headers
			MultiValueMap<String, String> headers = new HttpHeaders();
			headers.add("X-PowerAuth-Authorization", httpAuhtorizationHeader);

			// Send the activation status request to the server
			ActivationRemoveRequest requestObject = new ActivationRemoveRequest();
			PowerAuthAPIRequest<ActivationRemoveRequest> body = new PowerAuthAPIRequest<>();
			body.setRequestObject(requestObject);
			RequestEntity<PowerAuthAPIRequest<ActivationRemoveRequest>> request = new RequestEntity<PowerAuthAPIRequest<ActivationRemoveRequest>>(body, headers, HttpMethod.POST, uri);

			// Call the server with activation data
			System.out.println("Calling PowerAuth 2.0 Standard RESTful API at " + fullURIString + " ...");
			try {
				ResponseEntity<PowerAuthAPIResponse<ActivationRemoveResponse>> response = template.exchange(request, new ParameterizedTypeReference<PowerAuthAPIResponse<ActivationRemoveResponse>>() {
				});
				System.out.println("Done.");
				System.out.println();

				// Process the server response
				ActivationRemoveResponse responseObject = response.getBody().getResponseObject();
				String activationIdResponse = responseObject.getActivationId();

				// Print the results
				System.out.println("Activation ID: " + activationId);
				System.out.println("Server Activation ID: " + activationIdResponse);
				System.out.println();
				System.out.println("Activation remove complete.");
				System.out.println("### Done.");
				System.out.println();
			} catch (HttpClientErrorException exception) {
				String responseString = exception.getResponseBodyAsString();
				try {
					Map<String, Object> errorMap = mapper.readValue(responseString, Map.class);
					System.out.println(((Map<String, Object>) errorMap.get("error")).get("message"));
				} catch (Exception e) {
					System.out.println("Service error - HTTP " + exception.getStatusCode().toString() + ": " + exception.getStatusText());
				}
				System.out.println();
				System.out.println("### Failed.");
				System.out.println();
			} catch (ResourceAccessException exception) {
				System.out.println("Connection error - connection refused");
				System.out.println();
				System.out.println("### Failed.");
				System.out.println();
			} catch (Exception exception) {
				System.out.println("Unknown error - " + exception.getLocalizedMessage());
				System.out.println();
				System.out.println("### Failed.");
				System.out.println();
			}

		} else if (method.equals("sign")) {

			System.out.println("### PowerAuth 2.0 Client Signature Verification");
			System.out.println();

			// Prepare the activation URI
			String fullURIString = uriString + "/pa/signature/validate";
			URI uri = new URI(fullURIString);

			// Get data from status
			String activationId = (String) resultStatusObject.get("activationId");
			long counter = (long) resultStatusObject.get("counter");
			byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signaturePossessionKey"));
			byte[] signatureBiometryKeyBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureBiometryKey"));
			byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureKnowledgeKeySalt"));
			byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureKnowledgeKeyEncrypted"));

			// Ask for the password to unlock knowledge factor key
			Console console = System.console();
			char[] password = console.readPassword("Enter your password to unlock the knowledge related key: ");

			// Get the signature keys
			SecretKey signaturePossessionKey = keyConversion.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
			SecretKey signatureKnowledgeKey = this.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);
			SecretKey signatureBiometryKey = keyConversion.convertBytesToSharedSecretKey(signatureBiometryKeyBytes);

			// Generate nonce
			String pa_nonce = BaseEncoding.base64().encode(keyGenerator.generateRandomBytes(16));

			// Read input files
			String dataFileName = cmd.getOptionValue("d");
			byte[] statusFileBytes = null;
			if (Files.exists(Paths.get(dataFileName))) {
				statusFileBytes = Files.readAllBytes(Paths.get(dataFileName));
			} else {
				System.out.println("[WARN] Data file was not found!");
				System.out.println();
			}
			
			// Read the endpoint options
			String httpMethod = cmd.getOptionValue("h");
			String endpoint = cmd.getOptionValue("e");
			String signatureType = cmd.getOptionValue("l");

			// Compute the current PowerAuth 2.0 signature for possession and
			// knowledge factor
			String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(httpMethod, endpoint, getApplicationSecret(), pa_nonce, statusFileBytes);
			String pa_signature = signature.signatureForData(
					signatureBaseString.getBytes("UTF-8"), 
					keyFactory.keysForSignatureType(signatureType, signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey),
					counter
			);
			String httpAuhtorizationHeader = PowerAuthHttpHeader.getPowerAuthSignatureHTTPHeader(activationId, getApplicationId(), pa_nonce, PowerAuthConstants.SIGNATURE_TYPES.POSSESSION_KNOWLEDGE, pa_signature, "2.0");
			System.out.println("Coomputed X-PowerAuth-Authorization header: " + httpAuhtorizationHeader);
			System.out.println();

			// Increment the counter
			counter += 1;
			resultStatusObject.put("counter", new Long(counter));

			// Store the activation status (updated counter)
			String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(resultStatusObject);
			try (FileWriter file = new FileWriter(statusFileName)) {
				file.write(formatted);
			}

			// Prepare HTTP headers
			MultiValueMap<String, String> headers = new HttpHeaders();
			headers.add("X-PowerAuth-Authorization", httpAuhtorizationHeader);

			RequestEntity<byte[]> request = new RequestEntity<byte[]>(statusFileBytes, headers, HttpMethod.POST, uri);

			// Call the server with activation data
			System.out.println("Calling PowerAuth 2.0 Standard RESTful API at " + fullURIString + " ...");
			try {
				template.exchange(request, new ParameterizedTypeReference<PowerAuthAPIResponse<String>>() {
				});
				System.out.println("Done.");
				System.out.println();

				// Print the results
				System.out.println("Activation ID: " + activationId);
				System.out.println();
				System.out.println("Signature verification complete.");
				System.out.println("### Done.");
				System.out.println();
			} catch (HttpClientErrorException exception) {
				String responseString = exception.getResponseBodyAsString();
				try {
					Map<String, Object> errorMap = mapper.readValue(responseString, Map.class);
					System.out.println(((Map<String, Object>) errorMap.get("error")).get("message"));
				} catch (Exception e) {
					System.out.println("Service error - HTTP " + exception.getStatusCode().toString() + ": " + exception.getStatusText());
				}
				System.out.println();
				System.out.println("### Failed.");
				System.out.println();
			} catch (ResourceAccessException exception) {
				System.out.println("Connection error - connection refused");
				System.out.println();
				System.out.println("### Failed.");
				System.out.println();
			} catch (Exception exception) {
				System.out.println("Unknown error - " + exception.getLocalizedMessage());
				System.out.println();
				System.out.println("### Failed.");
				System.out.println();
			}

		} else if (method.equals("unlock")) {

		} else {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp("java -jar powerauth-java-client-app.jar", options);
			return;
		}

	}

	public byte[] storeSignatureKnowledgeKey(char[] password, SecretKey signatureKnoweldgeSecretKey, byte[] salt, KeyGenerator keyGenerator) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// Ask for the password and generate storage key
		SecretKey encryptionSignatureKnowledgeKey = keyGenerator.deriveSecretKeyFromPassword(new String(password), salt);

		// Encrypt the knowledge related key using the password derived key
		AESEncryptionUtils aes = new AESEncryptionUtils();
		byte[] signatureKnoweldgeSecretKeyBytes = new KeyConversionUtils().convertSharedSecretKeyToBytes(signatureKnoweldgeSecretKey);
		byte[] iv = new byte[16];
		byte[] cSignatureKnoweldgeSecretKey = aes.encrypt(signatureKnoweldgeSecretKeyBytes, iv, encryptionSignatureKnowledgeKey, "AES/CBC/NoPadding");
		return cSignatureKnoweldgeSecretKey;
	}

	public SecretKey getSignatureKnowledgeKey(char[] password, byte[] cSignatureKnoweldgeSecretKeyBytes, byte[] salt, KeyGenerator keyGenerator) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// Ask for the password and generate storage key
		SecretKey encryptionSignatureKnowledgeKey = keyGenerator.deriveSecretKeyFromPassword(new String(password), salt);

		// Encrypt the knowledge related key using the password derived key
		AESEncryptionUtils aes = new AESEncryptionUtils();
		byte[] iv = new byte[16];
		byte[] signatureKnoweldgeSecretKeyBytes = aes.decrypt(cSignatureKnoweldgeSecretKeyBytes, iv, encryptionSignatureKnowledgeKey, "AES/CBC/NoPadding");
		return new KeyConversionUtils().convertBytesToSharedSecretKey(signatureKnoweldgeSecretKeyBytes);
	}

}
