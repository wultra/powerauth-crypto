package io.getlime.security.powerauth.rest.api.jaxrs.encryption;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.powerauth.soap.PowerAuthPortServiceStub;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthNonPersonalizedEncryptor;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.soap.axis.client.PowerAuthServiceClient;

import javax.ejb.Stateless;
import javax.inject.Inject;
import java.rmi.RemoteException;

/**
 * Class responsible for building encryptors.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Stateless
public class EncryptorFactory {

    @Inject
    private PowerAuthServiceClient powerAuthClient;

    public EncryptorFactory() {
    }

    /**
     * Return a new instance of a non-personalized encryptor.
     * @param object Request object to be used to initialize a new encryptor.
     * @return New instance of a non-personalized encryptor.
     * @throws RemoteException In case a SOAP exception occurs.
     */
    public PowerAuthNonPersonalizedEncryptor buildNonPersonalizedEncryptor(ObjectRequest<NonPersonalizedEncryptedPayloadModel> object) throws RemoteException {
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
     * @throws RemoteException In case a SOAP exception occurs.
     */
    public PowerAuthNonPersonalizedEncryptor buildNonPersonalizedEncryptor(String applicationKeyBase64, String sessionIndexBase64, String ephemeralPublicKeyBase64) throws RemoteException {
        final PowerAuthPortServiceStub.GetNonPersonalizedEncryptionKeyResponse encryptionKeyResponse = powerAuthClient.generateNonPersonalizedE2EEncryptionKey(
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
