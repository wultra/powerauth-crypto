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
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.security.powerauth.rest.api.model.response.VaultUnlockResponse;
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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

/**
 * Helper class with vault unlock logics.
 *
 * @author Petr Dvorak
 *
 */
public class VaultUnlockStep {

    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientSignature signature = new PowerAuthClientSignature();
    private static final PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();
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
        String signatureType = (String) context.get("SIGNATURE_TYPE");
        String passwordProvided = (String) context.get("PASSWORD");

        System.out.println("### PowerAuth 2.0 Client Vault Unlock");
        System.out.println();

        // Prepare the activation URI
        String fullURIString = uriString + "/pa/vault/unlock";
        URI uri = new URI(fullURIString);

        // Get data from status
        String activationId = (String) resultStatusObject.get("activationId");
        long counter = (long) resultStatusObject.get("counter");
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signaturePossessionKey"));
        byte[] signatureBiometryKeyBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureBiometryKey"));
        byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureKnowledgeKeyEncrypted"));
        byte[] transportMasterKeyBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("transportMasterKey"));
        byte[] encryptedDevicePrivateKeyBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("encryptedDevicePrivateKey"));
        byte[] serverPublicKeyBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("serverPublicKey"));

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

        // Get the transport key
        SecretKey transportMasterKey = keyConversion.convertBytesToSharedSecretKey(transportMasterKeyBytes);

        // Generate nonce
        byte[] pa_nonce = keyGenerator.generateRandomBytes(16);

        // Compute the current PowerAuth 2.0 signature for possession and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("post", "/pa/vault/unlock", pa_nonce, null) + "&" + applicationSecret;
        String pa_signature = signature.signatureForData(signatureBaseString.getBytes("UTF-8"), keyFactory.keysForSignatureType(signatureType, signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), counter);
        String httpAuhtorizationHeader = PowerAuthHttpHeader.getPowerAuthSignatureHTTPHeader(activationId, applicationId, BaseEncoding.base64().encode(pa_nonce), PowerAuthSignatureTypes.getEnumFromString(signatureType).toString(), pa_signature, "2.0");

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

        RequestEntity<Void> request = new RequestEntity<>(null, headers, HttpMethod.POST, uri);

        RestTemplate template = RestTemplateFactory.defaultRestTemplate();

        // Call the server with activation data
        System.out.println("Calling PowerAuth 2.0 Standard RESTful API at " + fullURIString + " ...");
        System.out.println("Request headers: " + request.getHeaders().toString());
        System.out.println();
        try {
            ResponseEntity<PowerAuthApiResponse<VaultUnlockResponse>> response = template.exchange(request, new ParameterizedTypeReference<PowerAuthApiResponse<VaultUnlockResponse>>() {
            });
            System.out.println("Done.");
            System.out.println();

            String activationIdServer = response.getBody().getResponseObject().getActivationId();
            byte[] encryptedVaultEncryptionKey = BaseEncoding.base64().decode(response.getBody().getResponseObject().getEncryptedVaultEncryptionKey());

            PowerAuthClientVault vault = new PowerAuthClientVault();
            SecretKey vaultEncryptionKey = vault.decryptVaultEncryptionKey(encryptedVaultEncryptionKey, transportMasterKey, counter);
            PrivateKey devicePrivateKey = vault.decryptDevicePrivateKey(encryptedDevicePrivateKeyBytes, vaultEncryptionKey);
            PublicKey serverPublicKey = keyConversion.convertBytesToPublicKey(serverPublicKeyBytes);

            SecretKey masterSecretKey = keyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
            SecretKey transportKeyDeduced = keyFactory.generateServerTransportKey(masterSecretKey);
            boolean equal = transportKeyDeduced.equals(transportMasterKey);

            // Print the results
            System.out.println("Activation ID: " + activationId);
            System.out.println("Server activation ID: " + activationIdServer);
            System.out.println("Encrypted vault encryption key: " + BaseEncoding.base64().encode(encryptedVaultEncryptionKey));
            System.out.println("Transport master key: " + BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(transportMasterKey)));
            System.out.println("Vault encryption key: " + BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(vaultEncryptionKey)));
            System.out.println("Device Private Key: " + BaseEncoding.base64().encode(keyConversion.convertPrivateKeyToBytes(devicePrivateKey)));
            System.out.println("Result: " + (equal ? "OK" : "Broken"));
            System.out.println();
            System.out.println("Vault unlocking complete.");
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
