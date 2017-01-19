package io.getlime.security.powerauth.app.rest.api.spring.controller;

import io.getlime.powerauth.soap.CreateActivationResponse;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthNonPersonalizedEncryptor;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.provider.PowerAuthUserProvider;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiRequest;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.app.rest.api.spring.controller.model.ActivationCreateCustomRequest;
import io.getlime.security.powerauth.rest.api.model.request.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.ActivationCreateCustomResponse;
import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptorFactory;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.util.Map;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Controller
@RequestMapping(value = "/pa/activation/direct")
public class CustomActivationController {

    private PowerAuthServiceClient powerAuthClient;

    private EncryptorFactory encryptorFactory;

    private PowerAuthUserProvider userProvider;

    @Autowired
    public void setPowerAuthClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setEncryptorFactory(EncryptorFactory encryptorFactory) {
        this.encryptorFactory = encryptorFactory;
    }

    @Autowired(required = false)
    public void setUserProvider(PowerAuthUserProvider userProvider) {
        this.userProvider = userProvider;
    }

    @RequestMapping(value = "create", method = RequestMethod.POST)
    public @ResponseBody PowerAuthApiResponse<NonPersonalizedEncryptedPayloadModel> createNewActivation(
            @RequestBody PowerAuthApiRequest<NonPersonalizedEncryptedPayloadModel> object
    ) throws PowerAuthAuthenticationException, PowerAuthActivationException {
        try {

            // Check if there is any user provider to be autowired
            if (userProvider == null) {
                throw new PowerAuthActivationException();
            }

            // Prepare an encryptor
            final PowerAuthNonPersonalizedEncryptor encryptor = encryptorFactory.buildNonPersonalizedEncryptor(object);
            if (encryptor == null) {
                throw new PowerAuthActivationException();
            }

            // Decrypt the request object
            ActivationCreateCustomRequest request = encryptor.decrypt(object, ActivationCreateCustomRequest.class);

            // Lookup user ID using a provided identity
            final Map<String, String> identity = request.getIdentity();
            String userId = userProvider.lookupUserIdForAttributes(identity);

            // If no user was found, return error
            if (userId == null) {
                throw new PowerAuthActivationException();
            }

            // Create activation for a looked up user and application related to the given application key
            ActivationCreateRequest acr = request.getPowerauth();
            CreateActivationResponse response = powerAuthClient.createActivation(
                    acr.getApplicationKey(),
                    userId,
                    acr.getActivationIdShort(),
                    acr.getActivationName(),
                    acr.getActivationNonce(),
                    acr.getEphemeralPublicKey(),
                    acr.getEncryptedDevicePublicKey(),
                    acr.getExtras(),
                    acr.getApplicationSignature()
            );

            // Process custom attributes using a custom logic
            final Map<String, Object> customAttributes = request.getCustomAttributes();
            userProvider.processCustomActivationAttributes(customAttributes);

            // Prepare the created activation response data
            ActivationCreateCustomResponse createResponse = new ActivationCreateCustomResponse();
            createResponse.setActivationId(response.getActivationId());
            createResponse.setEphemeralPublicKey(response.getEphemeralPublicKey());
            createResponse.setActivationNonce(response.getActivationNonce());
            createResponse.setEncryptedServerPublicKey(response.getEncryptedServerPublicKey());
            createResponse.setEncryptedServerPublicKeySignature(response.getEncryptedServerPublicKeySignature());

            // Encrypt response object
            final PowerAuthApiResponse<NonPersonalizedEncryptedPayloadModel> powerAuthApiResponse = encryptor.encrypt(createResponse);

            // Check if activation should be committed instantly and if yes, perform commit
            if (userProvider.shouldAutoCommitActivation(identity, customAttributes)) {
                powerAuthClient.commitActivation(response.getActivationId());
            }

            // Return response
            return powerAuthApiResponse;

        } catch (IOException e) {
            throw new PowerAuthActivationException();
        }

    }

}
