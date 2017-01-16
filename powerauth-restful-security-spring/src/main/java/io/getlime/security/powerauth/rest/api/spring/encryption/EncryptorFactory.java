package io.getlime.security.powerauth.rest.api.spring.encryption;

import io.getlime.powerauth.soap.GetNonPersonalizedEncryptionKeyResponse;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthNonPersonalizedEncryptor;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiRequest;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Class responsible for building encryptors.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Component
public class EncryptorFactory {

    private PowerAuthServiceClient powerAuthClient;

    public EncryptorFactory() {
    }

    @Autowired
    public void setPowerAuthClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    /**
     * Return a new instance of a non-personalized encryptor.
     * @param object Request object to be used to initialize a new encryptor.
     * @return New instance of a non-personalized encryptor.
     */
    public PowerAuthNonPersonalizedEncryptor buildNonPersonalizedEncryptor(PowerAuthApiRequest<NonPersonalizedEncryptedPayloadModel> object) {
        return this.buildNonPersonalizedEncryptor(
                object.getRequestObject().getApplicationKey(),
                object.getRequestObject().getSessionIndex(),
                object.getRequestObject().getEphemeralPublicKey()
        );
    }

    /**
     * Return a new instance of a non-personalized encryptor.
     * @param applicationKeyBase64 Application key associated with an application master key used for encryption.
     * @param sessionIndexBase64 Session index.
     * @param ephemeralPublicKeyBase64 Ephemeral public key.
     * @return New instance of a non-personalized encryptor.
     */
    public PowerAuthNonPersonalizedEncryptor buildNonPersonalizedEncryptor(String applicationKeyBase64, String sessionIndexBase64, String ephemeralPublicKeyBase64) {
        final GetNonPersonalizedEncryptionKeyResponse encryptionKeyResponse = powerAuthClient.generateNonPersonalizedE2EEncryptionKey(
                applicationKeyBase64,
                ephemeralPublicKeyBase64,
                sessionIndexBase64
        );
        return new PowerAuthNonPersonalizedEncryptor(
                encryptionKeyResponse.getApplicationKey(),
                encryptionKeyResponse.getEncryptionKey(), encryptionKeyResponse.getEncryptionKeyIndex(),
                encryptionKeyResponse.getEphemeralPublicKey()
        );
    }

}
