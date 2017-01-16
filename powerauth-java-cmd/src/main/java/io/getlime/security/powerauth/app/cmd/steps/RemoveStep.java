/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.app.cmd.steps;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.app.cmd.util.RestTemplateFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.security.powerauth.rest.api.model.response.ActivationRemoveResponse;
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

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.FileWriter;
import java.net.URI;
import java.util.Arrays;
import java.util.Map;

/**
 * Helper class with activation remove logics.
 *
 * @author Petr Dvorak
 *
 */
public class RemoveStep {

    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientSignature signature = new PowerAuthClientSignature();
    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Execute this step with given context
     * @param context Provided context
     * @return Result status object, null in case of failure.
     * @throws Exception In case of any error.
     */
    @SuppressWarnings("unchecked")
    public static JSONObject execute(Map<String, Object> context) throws Exception {

        // Read properties from "context"
        String uriString = (String) context.get("URI_STRING");
        JSONObject resultStatusObject = (JSONObject) context.get("STATUS_OBJECT");
        String statusFileName = (String) context.get("STATUS_FILENAME");
        String applicationId = (String) context.get("APPLICATION_ID");
        String applicationSecret = (String) context.get("APPLICATION_SECRET");
        String passwordProvided = (String) context.get("PASSWORD");

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

        // Generate nonce
        byte[] pa_nonce = keyGenerator.generateRandomBytes(16);

        // Compute the current PowerAuth 2.0 signature for possession
        // and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/activation/remove", pa_nonce, null) + "&" + applicationSecret;
        String pa_signature = signature.signatureForData(signatureBaseString.getBytes("UTF-8"), Arrays.asList(signaturePossessionKey, signatureKnowledgeKey), counter);
        String httpAuhtorizationHeader = PowerAuthHttpHeader.getPowerAuthSignatureHTTPHeader(activationId, applicationId, BaseEncoding.base64().encode(pa_nonce), PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE.toString(), pa_signature, "2.0");
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
        headers.add(PowerAuthHttpHeader.HEADER_NAME, httpAuhtorizationHeader);

        // Send the activation status request to the server
        RequestEntity<Void> request = new RequestEntity<>(null, headers, HttpMethod.POST, uri);

        RestTemplate template = RestTemplateFactory.defaultRestTemplate();

        // Call the server with activation data
        System.out.println("Calling PowerAuth 2.0 Standard RESTful API at " + fullURIString + " ...");
        try {
            ResponseEntity<PowerAuthApiResponse<ActivationRemoveResponse>> response = template.exchange(request, new ParameterizedTypeReference<PowerAuthApiResponse<ActivationRemoveResponse>>() {
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