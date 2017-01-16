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
import io.getlime.security.powerauth.app.cmd.util.RestTemplateFactory;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiRequest;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.security.powerauth.rest.api.model.request.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.response.ActivationStatusResponse;
import org.json.simple.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import javax.crypto.SecretKey;
import java.net.URI;
import java.util.Map;

/**
 * Helper class with step for getting activation status.
 *
 * @author Petr Dvorak
 *
 */
public class GetStatusStep {

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();
    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Execute this step with given context
     * @param context Provided context
     * @return null
     * @throws Exception In case of any error.
     */
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
        PowerAuthApiRequest<ActivationStatusRequest> body = new PowerAuthApiRequest<>();
        body.setRequestObject(requestObject);
        RequestEntity<PowerAuthApiRequest<ActivationStatusRequest>> request = new RequestEntity<PowerAuthApiRequest<ActivationStatusRequest>>(body, HttpMethod.POST, uri);

        RestTemplate template = RestTemplateFactory.defaultRestTemplate();

        // Call the server with activation data
        System.out.println("Calling PowerAuth 2.0 Standard RESTful API at " + fullURIString + " ...");
        try {
            ResponseEntity<PowerAuthApiResponse<ActivationStatusResponse>> response = template.exchange(request, new ParameterizedTypeReference<PowerAuthApiResponse<ActivationStatusResponse>>() {
            });
            System.out.println("Done.");
            System.out.println();

            // Process the server response
            ActivationStatusResponse responseObject = response.getBody().getResponseObject();
            String activationIdResponse = responseObject.getActivationId();
            byte[] cStatusBlob = BaseEncoding.base64().decode(responseObject.getEncryptedStatusBlob());

            // Print the results
            ActivationStatusBlobInfo statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, transportMasterKey);
            System.out.println("Activation ID: " + activationId);
            System.out.println("Server Activation ID: " + activationIdResponse);
            System.out.println("Valid: " + statusBlob.isValid());
            System.out.println("Status: " + statusBlob.getActivationStatus());
            System.out.println("Counter: " + statusBlob.getCounter());
            System.out.println("Failures: " + statusBlob.getFailedAttempts());
            System.out.println("Max. Failures allowed: " + statusBlob.getMaxFailedAttempts());
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
