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
package io.getlime.security.client.app.steps;

import java.io.Console;
import java.io.FileWriter;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

import javax.crypto.SecretKey;

import org.json.simple.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;

import io.getlime.security.client.app.util.EncryptedStorageUtil;
import io.getlime.security.client.app.util.RestTemplateFactory;
import io.getlime.security.powerauth.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpHeader;

public class VerifySignatureStep {
	
	private static final KeyConversionUtils keyConversion = new KeyConversionUtils();
	private static final KeyGenerator keyGenerator = new KeyGenerator();
	private static final PowerAuthClientSignature signature = new PowerAuthClientSignature();
	private static final PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();
	private static final ObjectMapper mapper = new ObjectMapper();

	@SuppressWarnings("unchecked")
	public static JSONObject execute(Map<String, Object> context) throws Exception {
		
		// Read properties from "context"
		String uriString = (String) context.get("URI_STRING");
		JSONObject resultStatusObject = (JSONObject) context.get("STATUS_OBJECT");
		String statusFileName = (String)context.get("STATUS_FILENAME");
		String applicationId = (String)context.get("APPLICATION_ID");
		String applicationSecret = (String)context.get("APPLICATION_SECRET");
		String httpMethodString = ((String)context.get("HTTP_METHOD")).toUpperCase();
		String endpoint = (String)context.get("ENDPOINT");
		String signatureType = (String)context.get("SIGNATURE_TYPE");
		String dataFileName = (String)context.get("DATA_FILE_NAME");
		String passwordProvided = (String)context.get("PASSWORD");
		
		System.out.println("### PowerAuth 2.0 Client Signature Verification");
		System.out.println();

		// Prepare the activation URI
		String fullURIString = uriString;
		URI uri = new URI(fullURIString);

		// Get data from status
		String activationId = (String) resultStatusObject.get("activationId");
		long counter = (long) resultStatusObject.get("counter");
		byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signaturePossessionKey"));
		byte[] signatureBiometryKeyBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureBiometryKey"));
		byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureKnowledgeKeySalt"));
		byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureKnowledgeKeyEncrypted"));

		// Ask for the password to unlock knowledge factor key
		char[] password = null;
		if (passwordProvided == null) {
			Console console = System.console();
			password = console.readPassword("Enter your password to unlock the knowledge related key: ");
		} else {
			password = passwordProvided.toCharArray();
		}

		// Get the signature keys
		SecretKey signaturePossessionKey = keyConversion.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
		SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);
		SecretKey signatureBiometryKey = keyConversion.convertBytesToSharedSecretKey(signatureBiometryKeyBytes);

		// Generate nonce
		String pa_nonce = BaseEncoding.base64().encode(keyGenerator.generateRandomBytes(16));

		// Read data input file
		byte[] dataFileBytes = null;
		if (dataFileName != null && Files.exists(Paths.get(dataFileName))) {
			dataFileBytes = Files.readAllBytes(Paths.get(dataFileName));
		} else {
			System.out.println("[WARN] Data file was not found!");
			System.out.println();
		}

		// Compute the current PowerAuth 2.0 signature for possession and knowledge factor
		String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(httpMethodString, endpoint, applicationSecret, pa_nonce, dataFileBytes);
		String pa_signature = signature.signatureForData(signatureBaseString.getBytes("UTF-8"), keyFactory.keysForSignatureType(signatureType, signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), counter);
		String httpAuhtorizationHeader = PowerAuthHttpHeader.getPowerAuthSignatureHTTPHeader(activationId, applicationId, pa_nonce, PowerAuthSignatureTypes.getEnumFromString(signatureType), pa_signature, "2.0");

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
		
		// Parse HTTP method
		HttpMethod httpMethod = HttpMethod.valueOf(httpMethodString);

		RequestEntity<byte[]> request = new RequestEntity<byte[]>(dataFileBytes, headers, httpMethod, uri);
		
		RestTemplate template = RestTemplateFactory.defaultRestTemplate();

		// Call the server with activation data
		System.out.println("Calling PowerAuth 2.0 Standard RESTful API at " + fullURIString + " ...");
		System.out.println("Request headers: " + request.getHeaders().toString());
		System.out.println("Request method: " + httpMethod.toString());
		if (dataFileBytes != null) {
			System.out.println("Request body: " + new String(dataFileBytes, "UTF-8"));
		}
		System.out.println();
		try {
			ResponseEntity<Map<String, Object>> response = template.exchange(request, new ParameterizedTypeReference<Map<String, Object>>() {
			});
			System.out.println("Done.");
			System.out.println();

			// Print the results
			System.out.println("Activation ID: " + activationId);
			System.out.println();
			System.out.println("Response received");
			System.out.println("Response code: " + response.getStatusCode());
			System.out.println("Response headers: " + response.getHeaders().toString());
			System.out.println("Response body: " + response.getBody());
			System.out.println();
			System.out.println("Signature verification complete.");
			System.out.println("### Done.");
			System.out.println();
			return resultStatusObject;
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
			System.exit(1);
		} catch (ResourceAccessException exception) {
			System.out.println("Connection error - connection refused");
			System.out.println();
			System.out.println("### Failed.");
			System.out.println();
			System.exit(1);
		} catch (Exception exception) {
			System.out.println("Unknown error - " + exception.getLocalizedMessage());
			System.out.println();
			System.out.println("### Failed.");
			System.out.println();
			System.exit(1);
		}
		return null;
	}
	
}
