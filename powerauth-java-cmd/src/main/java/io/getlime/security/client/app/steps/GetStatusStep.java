package io.getlime.security.client.app.steps;

import java.net.URI;
import java.util.Map;

import javax.crypto.SecretKey;

import org.json.simple.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;

import io.getlime.rest.api.model.ActivationStatusRequest;
import io.getlime.rest.api.model.ActivationStatusResponse;
import io.getlime.rest.api.model.PowerAuthAPIRequest;
import io.getlime.rest.api.model.PowerAuthAPIResponse;
import io.getlime.security.client.app.util.RestTemplateFactory;
import io.getlime.security.powerauth.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;

public class GetStatusStep {
	
	private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();
	private static final KeyConversionUtils keyConversion = new KeyConversionUtils();
	private static final ObjectMapper mapper = new ObjectMapper();

	@SuppressWarnings("unchecked")
	public static JSONObject execute(Map<String, Object> context) throws Exception {
		
		// Read properties from "context"
		String uriString = (String) context.get("URI_STRING");
		JSONObject resultStatusObject = (JSONObject) context.get("STATUS_OBJECT");
		
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
		
		RestTemplate template = RestTemplateFactory.defaultRestTemplate();

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
