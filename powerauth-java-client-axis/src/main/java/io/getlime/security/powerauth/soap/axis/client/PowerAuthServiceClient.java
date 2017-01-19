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

package io.getlime.security.powerauth.soap.axis.client;


import io.getlime.powerauth.soap.PowerAuthPortServiceStub;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;

import java.rmi.RemoteException;
import java.util.Arrays;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

/**
 * Class implementing a PowerAuth SOAP service client based on provided WSDL
 * service description. This class uses Axis 2 under the hood.
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthServiceClient {

    private PowerAuthPortServiceStub clientStub;

    /**
     * Create a SOAP service client with the default URL:
     *
     * - http://localhost:8080/powerauth-java-server/soap
     *
     * @throws AxisFault When the Axis2 setup fails.
     */
    public PowerAuthServiceClient() throws AxisFault {
        this.clientStub = new PowerAuthPortServiceStub();
    }

    /**
     * Create a SOAP service client with the URI provided in parameter.
     * @param serviceUri SOAP service URI.
     * @throws AxisFault When the Axis2 setup fails.
     */
    public PowerAuthServiceClient(String serviceUri) throws AxisFault {
        this.clientStub = new PowerAuthPortServiceStub(serviceUri);
    }

    /**
     * Create a SOAP service client with the provided PowerAuthPortServiceStub instance.
     * @param clientStub Axis2 client stub.
     */
    public PowerAuthServiceClient(PowerAuthPortServiceStub clientStub) {
        this.clientStub = clientStub;
    }

    /**
     * Set the Axis2 client stub.
     * @param clientStub Client stub.
     */
    public void setClientStub(PowerAuthPortServiceStub clientStub) {
        this.clientStub = clientStub;
    }

    /**
     * Get the Axis2 client stub.
     * @return Client stub.
     */
    public PowerAuthPortServiceStub getClientStub() {
        return clientStub;
    }

    /**
     * Set the SOAP service endpoint URI.
     * @param uri SOAP service URI.
     */
    public void setServiceUri(String uri) {
        clientStub._getServiceClient().getOptions().setTo(new EndpointReference(uri));
    }

    /**
     * Convert date to GregorianCalendar
     * @param date Date to be converted.
     * @return A new instance of {@link GregorianCalendar}.
     */
    private GregorianCalendar calendarWithDate(Date date) {
        GregorianCalendar c = new GregorianCalendar();
        c.setTime(date);
        return c;
    }

    /**
     * Call the getSystemStatus method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetSystemStatusRequest} instance
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetSystemStatusResponse}
     */
    public PowerAuthPortServiceStub.GetSystemStatusResponse getSystemStatus(PowerAuthPortServiceStub.GetSystemStatusRequest request) throws RemoteException {
        return clientStub.getSystemStatus(request);
    }

    /**
     * Call the getSystemStatus method of the PowerAuth 2.0 Server SOAP interface.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetSystemStatusResponse}
     */
    public PowerAuthPortServiceStub.GetSystemStatusResponse getSystemStatus() throws RemoteException {
        PowerAuthPortServiceStub.GetSystemStatusRequest request = new PowerAuthPortServiceStub.GetSystemStatusRequest();
        return clientStub.getSystemStatus(request);
    }

    /**
     * Call the initActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.InitActivationRequest} instance
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.InitActivationResponse}
     */
    public PowerAuthPortServiceStub.InitActivationResponse initActivation(PowerAuthPortServiceStub.InitActivationRequest request) throws RemoteException {
        return clientStub.initActivation(request);
    }

    /**
     * Call the initActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param userId User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.InitActivationResponse}
     */
    public PowerAuthPortServiceStub.InitActivationResponse initActivation(String userId, Long applicationId) throws RemoteException {
        return this.initActivation(userId, applicationId, null, null);
    }

    /**
     * Call the initActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param userId User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @param maxFailureCount How many failed attempts should be allowed for this activation.
     * @param timestampActivationExpire Timestamp until when the activation can be committed.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.InitActivationResponse}
     */
    public PowerAuthPortServiceStub.InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire) throws RemoteException {
        PowerAuthPortServiceStub.InitActivationRequest request = new PowerAuthPortServiceStub.InitActivationRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        if (maxFailureCount != null) {
            request.setMaxFailureCount(maxFailureCount);
        }
        if (timestampActivationExpire != null) {
            request.setTimestampActivationExpire(calendarWithDate(timestampActivationExpire));
        }
        return this.initActivation(request);
    }

    /**
     * Call the prepareActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.PrepareActivationRequest} instance
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.PrepareActivationResponse}
     */
    public PowerAuthPortServiceStub.PrepareActivationResponse prepareActivation(PowerAuthPortServiceStub.PrepareActivationRequest request) throws RemoteException {
        return clientStub.prepareActivation(request);
    }

    /**
     * Call the prepareActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationIdShort Short activation ID.
     * @param activationName Name of this activation.
     * @param activationNonce Activation nonce.
     * @param applicationKey Application key of a given application.
     * @param applicationSignature Signature proving a correct application is sending the data.
     * @param cDevicePublicKey Device public key encrypted with activation OTP.
     * @param extras Additional, application specific information.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.PrepareActivationResponse}
     */
    public PowerAuthPortServiceStub.PrepareActivationResponse prepareActivation(String activationIdShort, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationKey, String applicationSignature) throws RemoteException {
        PowerAuthPortServiceStub.PrepareActivationRequest request = new PowerAuthPortServiceStub.PrepareActivationRequest();
        request.setActivationIdShort(activationIdShort);
        request.setActivationName(activationName);
        request.setActivationNonce(activationNonce);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedDevicePublicKey(cDevicePublicKey);
        request.setExtras(extras);
        request.setApplicationKey(applicationKey);
        request.setApplicationSignature(applicationSignature);
        return this.prepareActivation(request);
    }

    /**
     * Create a new activation directly, using the createActivation method of the PowerAuth 2.0 Server
     * SOAP interface.
     * @param request Create activation request.
     * @return Create activation response.
     */
    public PowerAuthPortServiceStub.CreateActivationResponse createActivation(PowerAuthPortServiceStub.CreateActivationRequest request) throws RemoteException {
        return clientStub.createActivation(request);
    }

    /**
     * Call the createActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param userId User ID.
     * @param applicationKey Application key of a given application.
     * @param identity Identity fingerprint used during activation.
     * @param activationName Name of this activation.
     * @param activationNonce Activation nonce.
     * @param applicationSignature Signature proving a correct application is sending the data.
     * @param cDevicePublicKey Device public key encrypted with activation OTP.
     * @param ephemeralPublicKey Ephemeral public key used for one-time object transfer.
     * @param extras Additional, application specific information.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.CreateActivationResponse}
     */
    public PowerAuthPortServiceStub.CreateActivationResponse createActivation(String applicationKey, String userId, String identity, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws RemoteException {
        return this.createActivation(
                applicationKey,
                userId,
                null,
                null,
                identity,
                "00000-00000",
                activationName,
                activationNonce,
                ephemeralPublicKey,
                cDevicePublicKey,
                extras,
                applicationSignature
        );
    }

    /**
     * Call the createActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param userId User ID.
     * @param maxFailureCount Maximum failure count.
     * @param timestampActivationExpire Timestamp this activation should expire.
     * @param applicationKey Application key of a given application.
     * @param identity Identity fingerprint used during activation.
     * @param activationOtp Activation OTP.
     * @param activationName Name of this activation.
     * @param activationNonce Activation nonce.
     * @param applicationSignature Signature proving a correct application is sending the data.
     * @param cDevicePublicKey Device public key encrypted with activation OTP.
     * @param ephemeralPublicKey Ephemeral public key used for one-time object transfer.
     * @param extras Additional, application specific information.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.CreateActivationResponse}
     */
    public PowerAuthPortServiceStub.CreateActivationResponse createActivation(String applicationKey, String userId, Long maxFailureCount, Date timestampActivationExpire, String identity, String activationOtp, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) throws RemoteException {
        PowerAuthPortServiceStub.CreateActivationRequest request = new PowerAuthPortServiceStub.CreateActivationRequest();
        request.setApplicationKey(applicationKey);
        request.setUserId(userId);
        if (maxFailureCount != null) {
            request.setMaxFailureCount(maxFailureCount);
        }
        if (timestampActivationExpire != null) {
            request.setTimestampActivationExpire(calendarWithDate(timestampActivationExpire));
        }
        request.setIdentity(identity);
        request.setActivationOtp(activationOtp);
        request.setActivationName(activationName);
        request.setActivationNonce(activationNonce);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedDevicePublicKey(cDevicePublicKey);
        request.setExtras(extras);
        request.setApplicationSignature(applicationSignature);
        return this.createActivation(request);
    }

    /**
     * Call the commitActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.CommitActivationRequest} instance
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.CommitActivationResponse}
     */
    public PowerAuthPortServiceStub.CommitActivationResponse commitActivation(PowerAuthPortServiceStub.CommitActivationRequest request) throws RemoteException {
        return clientStub.commitActivation(request);
    }

    /**
     * Call the prepareActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID for activation to be committed.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.CommitActivationResponse}
     */
    public PowerAuthPortServiceStub.CommitActivationResponse commitActivation(String activationId) throws RemoteException {
        PowerAuthPortServiceStub.CommitActivationRequest request = new PowerAuthPortServiceStub.CommitActivationRequest();
        request.setActivationId(activationId);
        return this.commitActivation(request);
    }

    /**
     * Call the getActivationStatus method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetActivationStatusRequest} instance
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetActivationStatusResponse}
     */
    public PowerAuthPortServiceStub.GetActivationStatusResponse getActivationStatus(PowerAuthPortServiceStub.GetActivationStatusRequest request) throws RemoteException {
        return clientStub.getActivationStatus(request);
    }

    /**
     * Call the getActivationStatus method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation Id to lookup information for.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetActivationStatusResponse}
     */
    public PowerAuthPortServiceStub.GetActivationStatusResponse getActivationStatus(String activationId) throws RemoteException {
        PowerAuthPortServiceStub.GetActivationStatusRequest request = new PowerAuthPortServiceStub.GetActivationStatusRequest();
        request.setActivationId(activationId);
        return this.getActivationStatus(request);
    }

    /**
     * Call the getActivationListForUser method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetActivationListForUserRequest} instance
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetActivationListForUserResponse}
     */
    public PowerAuthPortServiceStub.GetActivationListForUserResponse getActivationListForUser(PowerAuthPortServiceStub.GetActivationListForUserRequest request) throws RemoteException {
        return clientStub.getActivationListForUser(request);
    }

    /**
     * Call the getActivationListForUser method of the PowerAuth 2.0 Server SOAP interface.
     * @param userId User ID to fetch the activations for.
     * @return List of activation instances for given user.
     */
    public List<PowerAuthPortServiceStub.Activations_type0> getActivationListForUser(String userId) throws RemoteException {
        PowerAuthPortServiceStub.GetActivationListForUserRequest request = new PowerAuthPortServiceStub.GetActivationListForUserRequest();
        request.setUserId(userId);
        return Arrays.asList(this.getActivationListForUser(request).getActivations());
    }

    /**
     * Call the removeActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.RemoveActivationRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.RemoveActivationResponse}
     */
    public PowerAuthPortServiceStub.RemoveActivationResponse removeActivation(PowerAuthPortServiceStub.RemoveActivationRequest request) throws RemoteException {
        return clientStub.removeActivation(request);
    }

    /**
     * Call the removeActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be removed.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.RemoveActivationResponse}
     */
    public PowerAuthPortServiceStub.RemoveActivationResponse removeActivation(String activationId) throws RemoteException {
        PowerAuthPortServiceStub.RemoveActivationRequest request = new PowerAuthPortServiceStub.RemoveActivationRequest();
        request.setActivationId(activationId);
        return this.removeActivation(request);
    }

    /**
     * Call the blockActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.BlockActivationRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.BlockActivationResponse}
     */
    public PowerAuthPortServiceStub.BlockActivationResponse blockActivation(PowerAuthPortServiceStub.BlockActivationRequest request) throws RemoteException {
        return clientStub.blockActivation(request);
    }

    /**
     * Call the blockActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be blocked.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.BlockActivationResponse}
     */
    public PowerAuthPortServiceStub.BlockActivationResponse blockActivation(String activationId) throws RemoteException {
        PowerAuthPortServiceStub.BlockActivationRequest request = new PowerAuthPortServiceStub.BlockActivationRequest();
        request.setActivationId(activationId);
        return this.blockActivation(request);
    }

    /**
     * Call the unblockActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.UnblockActivationRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.UnblockActivationResponse}
     */
    public PowerAuthPortServiceStub.UnblockActivationResponse unblockActivation(PowerAuthPortServiceStub.UnblockActivationRequest request) throws RemoteException {
        return clientStub.unblockActivation(request);
    }

    /**
     * Call the unblockActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be unblocked.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.UnblockActivationResponse}
     */
    public PowerAuthPortServiceStub.UnblockActivationResponse unblockActivation(String activationId) throws RemoteException {
        PowerAuthPortServiceStub.UnblockActivationRequest request = new PowerAuthPortServiceStub.UnblockActivationRequest();
        request.setActivationId(activationId);
        return this.unblockActivation(request);
    }

    /**
     * Call the vaultUnlock method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.VaultUnlockRequest} instance
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.VaultUnlockResponse}
     */
    public PowerAuthPortServiceStub.VaultUnlockResponse unlockVault(PowerAuthPortServiceStub.VaultUnlockRequest request) throws RemoteException {
        return clientStub.vaultUnlock(request);
    }

    /**
     * Call the vaultUnlock method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation Id of an activation to be used for authentication.
     * @param applicationKey Application Key of an application related to the activation.
     * @param data Data to be signed encoded in format as specified by PowerAuth 2.0 data normalization.
     * @param signature Vault opening request signature.
     * @param signatureType Vault opening request signature type.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.VaultUnlockResponse}
     */
    public PowerAuthPortServiceStub.VaultUnlockResponse unlockVault(String activationId, String applicationKey, String data, String signature, String signatureType) throws RemoteException {
        PowerAuthPortServiceStub.VaultUnlockRequest request = new PowerAuthPortServiceStub.VaultUnlockRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setData(data);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        return this.unlockVault(request);
    }

    /**
     * Call the verifySignature method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.VerifySignatureRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.VerifySignatureResponse}
     */
    public PowerAuthPortServiceStub.VerifySignatureResponse verifySignature(PowerAuthPortServiceStub.VerifySignatureRequest request) throws RemoteException {
        return clientStub.verifySignature(request);
    }

    /**
     * Call the verifySignature method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be used for authentication.
     * @param applicationKey Application Key of an application related to the activation.
     * @param data Data to be signed encoded in format as specified by PowerAuth 2.0 data normalization.
     * @param signature Request signature.
     * @param signatureType Request signature type.
     * @return Verify signature and return SOAP response with the verification results.
     */
    public PowerAuthPortServiceStub.VerifySignatureResponse verifySignature(String activationId, String applicationKey, String data, String signature, String signatureType) throws RemoteException {
        PowerAuthPortServiceStub.VerifySignatureRequest request = new PowerAuthPortServiceStub.VerifySignatureRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setData(data);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        return this.verifySignature(request);
    }

    /**
     * Call the verifyECDSASignature method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.VerifyECDSASignatureRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.VerifyECDSASignatureResponse}
     */
    public PowerAuthPortServiceStub.VerifyECDSASignatureResponse verifyECDSASignature(PowerAuthPortServiceStub.VerifyECDSASignatureRequest request) throws RemoteException {
        return clientStub.verifyECDSASignature(request);
    }

    /**
     * Call the verifyECDSASignature method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be used for authentication.
     * @param data Data that were signed by ECDSA algorithm.
     * @param signature Request signature.
     * @return Verify ECDSA signature and return SOAP response with the verification results.
     */
    public PowerAuthPortServiceStub.VerifyECDSASignatureResponse verifyECDSASignature(String activationId, String data, String signature) throws RemoteException {
        PowerAuthPortServiceStub.VerifyECDSASignatureRequest request = new PowerAuthPortServiceStub.VerifyECDSASignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        return this.verifyECDSASignature(request);
    }

    /**
     * Call the generateE2EPersonalziedEncryptionKey method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetPersonalizedEncryptionKeyRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetPersonalizedEncryptionKeyResponse}
     */
    public PowerAuthPortServiceStub.GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(PowerAuthPortServiceStub.GetPersonalizedEncryptionKeyRequest request) throws RemoteException {
        return clientStub.getPersonalizedEncryptionKey(request);
    }

    /**
     * Call the generateE2EPersonalziedEncryptionKey method of the PowerAuth 2.0 Server SOAP interface and get
     * newly generated derived encryption key.
     * @param activationId Activation ID used for the key generation.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetPersonalizedEncryptionKeyResponse}
     */
    public PowerAuthPortServiceStub.GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(String activationId, String sessionIndex) throws RemoteException {
        PowerAuthPortServiceStub.GetPersonalizedEncryptionKeyRequest request = new PowerAuthPortServiceStub.GetPersonalizedEncryptionKeyRequest();
        request.setActivationId(activationId);
        request.setSessionIndex(sessionIndex);
        return this.generatePersonalizedE2EEncryptionKey(request);
    }

    /**
     * Call the generateE2ENonPersonalizedEncryptionKey method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetNonPersonalizedEncryptionKeyRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetNonPersonalizedEncryptionKeyResponse}
     */
    public PowerAuthPortServiceStub.GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(PowerAuthPortServiceStub.GetNonPersonalizedEncryptionKeyRequest request) throws RemoteException {
        return clientStub.getNonPersonalizedEncryptionKey(request);
    }

    /**
     * Call the generateE2ENonPersonalizedEncryptionKey method of the PowerAuth 2.0 Server SOAP interface and get
     * newly generated derived encryption key.
     * @param applicationKey Application key related to application used for the key generation.
     * @param ephemeralPublicKeyBase64 Ephemeral public key.
     * @param sessionIndex Session index.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetNonPersonalizedEncryptionKeyResponse}
     */
    public PowerAuthPortServiceStub.GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(String applicationKey, String ephemeralPublicKeyBase64, String sessionIndex) throws RemoteException {
        PowerAuthPortServiceStub.GetNonPersonalizedEncryptionKeyRequest request = new PowerAuthPortServiceStub.GetNonPersonalizedEncryptionKeyRequest();
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKeyBase64);
        request.setSessionIndex(sessionIndex);
        return this.generateNonPersonalizedE2EEncryptionKey(request);
    }

    /**
     * Call the getSignatureAuditLog method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.SignatureAuditRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.SignatureAuditResponse}
     */
    public PowerAuthPortServiceStub.SignatureAuditResponse getSignatureAuditLog(PowerAuthPortServiceStub.SignatureAuditRequest request) throws RemoteException {
        return clientStub.signatureAudit(request);
    }

    /**
     * Call the verifySignature method of the PowerAuth 2.0 Server SOAP interface and get
     * signature audit log for all application of a given user.
     * @param userId User ID to query the audit log against.
     * @param startingDate Limit the results to given starting date (= "newer than")
     * @param endingDate Limit the results to given ending date (= "older than")
     * @return List of signature audit items {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.Items_type0}
     */
    public List<PowerAuthPortServiceStub.Items_type0> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) throws RemoteException {
        PowerAuthPortServiceStub.SignatureAuditRequest request = new PowerAuthPortServiceStub.SignatureAuditRequest();
        request.setUserId(userId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return Arrays.asList(this.getSignatureAuditLog(request).getItems());
    }

    /**
     * Call the verifySignature method of the PowerAuth 2.0 Server SOAP interface and get
     * signature audit log for a single application.
     * @param userId User ID to query the audit log against.
     * @param applicationId Application ID to query the audit log against.
     * @param startingDate Limit the results to given starting date (= "newer than")
     * @param endingDate Limit the results to given ending date (= "older than")
     * @return List of signature audit items {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.Items_type0}
     */
    public List<PowerAuthPortServiceStub.Items_type0> getSignatureAuditLog(String userId, Long applicationId, Date startingDate, Date endingDate) throws RemoteException {
        PowerAuthPortServiceStub.SignatureAuditRequest request = new PowerAuthPortServiceStub.SignatureAuditRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return Arrays.asList(this.getSignatureAuditLog(request).getItems());
    }

    /**
     * Get the list of all applications that are registered in PowerAuth 2.0 Server.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetApplicationListRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetApplicationListResponse}
     */
    public PowerAuthPortServiceStub.GetApplicationListResponse getApplicationList(PowerAuthPortServiceStub.GetApplicationListRequest request) throws RemoteException {
        return clientStub.getApplicationList(request);
    }

    /**
     * Get the list of all applications that are registered in PowerAuth 2.0 Server.
     * @return List of applications.
     */
    public List<PowerAuthPortServiceStub.Applications_type0> getApplicationList() throws RemoteException {
        PowerAuthPortServiceStub.GetApplicationListRequest request = new PowerAuthPortServiceStub.GetApplicationListRequest();
        return Arrays.asList(this.getApplicationList(request).getApplications());
    }

    /**
     * Return the detail of given application, including all application versions.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetApplicationDetailRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.GetApplicationDetailResponse}
     */
    public PowerAuthPortServiceStub.GetApplicationDetailResponse getApplicationDetail(PowerAuthPortServiceStub.GetApplicationDetailRequest request) throws RemoteException {
        return clientStub.getApplicationDetail(request);
    }

    /**
     * Get the detail of an application with given ID, including the version list.
     * @param applicationId ID of an application to fetch.
     * @return Application with given ID, including the version list.
     */
    public PowerAuthPortServiceStub.GetApplicationDetailResponse getApplicationDetail(Long applicationId) throws RemoteException {
        PowerAuthPortServiceStub.GetApplicationDetailRequest request = new PowerAuthPortServiceStub.GetApplicationDetailRequest();
        request.setApplicationId(applicationId);
        return this.getApplicationDetail(request);
    }

    /**
     * Create a new application with given name.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.CreateApplicationRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.CreateApplicationResponse}
     */
    public PowerAuthPortServiceStub.CreateApplicationResponse createApplication(PowerAuthPortServiceStub.CreateApplicationRequest request) throws RemoteException {
        return clientStub.createApplication(request);
    }

    /**
     * Create a new application with given name.
     * @param name Name of the new application.
     * @return Application with a given name.
     */
    public PowerAuthPortServiceStub.CreateApplicationResponse createApplication(String name) throws RemoteException {
        PowerAuthPortServiceStub.CreateApplicationRequest request = new PowerAuthPortServiceStub.CreateApplicationRequest();
        request.setApplicationName(name);
        return this.createApplication(request);
    }

    /**
     * Create a version with a given name for an application with given ID.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.CreateApplicationVersionRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.CreateApplicationVersionResponse}
     */
    public PowerAuthPortServiceStub.CreateApplicationVersionResponse createApplicationVersion(PowerAuthPortServiceStub.CreateApplicationVersionRequest request) throws RemoteException {
        return clientStub.createApplicationVersion(request);
    }

    /**
     * Create a version with a given name for an application with given ID.
     * @param applicationId ID of an application to create a version for.
     * @param versionName Name of the version. The value should follow some well received conventions (such as "1.0.3", for example).
     * @return A new version with a given name and application key / secret.
     */
    public PowerAuthPortServiceStub.CreateApplicationVersionResponse createApplicationVersion(Long applicationId, String versionName) throws RemoteException {
        PowerAuthPortServiceStub.CreateApplicationVersionRequest request = new PowerAuthPortServiceStub.CreateApplicationVersionRequest();
        request.setApplicationId(applicationId);
        request.setApplicationVersionName(versionName);
        return this.createApplicationVersion(request);
    }

    /**
     * Cancel the support for a given application version.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.UnsupportApplicationVersionRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.UnsupportApplicationVersionResponse}
     */
    public PowerAuthPortServiceStub.UnsupportApplicationVersionResponse unsupportApplicationVersion(PowerAuthPortServiceStub.UnsupportApplicationVersionRequest request) throws RemoteException {
        return clientStub.unsupportApplicationVersion(request);
    }

    /**
     * Cancel the support for a given application version.
     * @param versionId Version to be unsupported.
     * @return Information about success / failure.
     */
    public PowerAuthPortServiceStub.UnsupportApplicationVersionResponse unsupportApplicationVersion(Long versionId) throws RemoteException {
        PowerAuthPortServiceStub.UnsupportApplicationVersionRequest request = new PowerAuthPortServiceStub.UnsupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.unsupportApplicationVersion(request);
    }

    /**
     * Renew the support for a given application version.
     * @param request {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.SupportApplicationVersionRequest} instance.
     * @return {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.SupportApplicationVersionResponse}
     */
    public PowerAuthPortServiceStub.SupportApplicationVersionResponse supportApplicationVersion(PowerAuthPortServiceStub.SupportApplicationVersionRequest request) throws RemoteException {
        return clientStub.supportApplicationVersion(request);
    }

    /**
     * Renew the support for a given application version.
     * @param versionId Version to be supported again.
     * @return Information about success / failure.
     */
    public PowerAuthPortServiceStub.SupportApplicationVersionResponse supportApplicationVersion(Long versionId) throws RemoteException {
        PowerAuthPortServiceStub.SupportApplicationVersionRequest request = new PowerAuthPortServiceStub.SupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.supportApplicationVersion(request);
    }

    /**
     * Create a new integration with given name.
     * @param request Request specifying the integration name.
     * @return New integration information.
     */
    public PowerAuthPortServiceStub.CreateIntegrationResponse createIntegration(PowerAuthPortServiceStub.CreateIntegrationRequest request) throws RemoteException {
        return clientStub.createIntegration(request);
    }

    /**
     * Create a new integration with given name.
     * @param name Integration name.
     * @return New integration information.
     */
    public PowerAuthPortServiceStub.CreateIntegrationResponse createIntegration(String name) throws RemoteException {
        PowerAuthPortServiceStub.CreateIntegrationRequest request = new PowerAuthPortServiceStub.CreateIntegrationRequest();
        request.setName(name);
        return this.createIntegration(request);
    }

    /**
     * Get the list of integrations.
     * @param request SOAP request object.
     * @return List of integrations.
     */
    public PowerAuthPortServiceStub.GetIntegrationListResponse getIntegrationList(PowerAuthPortServiceStub.GetIntegrationListRequest request) throws RemoteException {
        return clientStub.getIntegrationList(request);
    }

    /**
     * Get the list of integrations.
     * @return List of integrations.
     */
    public List<PowerAuthPortServiceStub.Items_type1> getIntegrationList() throws RemoteException {
        PowerAuthPortServiceStub.GetIntegrationListRequest request = new PowerAuthPortServiceStub.GetIntegrationListRequest();
        return Arrays.asList(this.getIntegrationList(request).getItems());
    }

    /**
     * Remove integration with given ID.
     * @param request SOAP object with integration ID to be removed.
     * @return Removal status.
     */
    public PowerAuthPortServiceStub.RemoveIntegrationResponse removeIntegration(PowerAuthPortServiceStub.RemoveIntegrationRequest request) throws RemoteException {
        return clientStub.removeIntegration(request);
    }

    /**
     * Remove integration with given ID.
     * @param id ID of integration to be removed.
     * @return Removal status.
     */
    public PowerAuthPortServiceStub.RemoveIntegrationResponse removeIntegration(String id) throws RemoteException {
        PowerAuthPortServiceStub.RemoveIntegrationRequest request = new PowerAuthPortServiceStub.RemoveIntegrationRequest();
        request.setId(id);
        return this.removeIntegration(request);
    }


    /**
     * Create a new callback URL with given request object.
     * @param request SOAP request object with callback URL details.
     * @return Information about new callback URL object.
     */
    public PowerAuthPortServiceStub.CreateCallbackUrlResponse createCallbackUrl(PowerAuthPortServiceStub.CreateCallbackUrlRequest request) throws RemoteException {
        return clientStub.createCallbackUrl(request);
    }

    /**
     * Create a new callback URL with given parameters.
     * @param applicationId Application ID.
     * @param name Callback URL display name.
     * @param callbackUrl Callback URL value.
     * @return Information about new callback URL object.
     */
    public PowerAuthPortServiceStub.CreateCallbackUrlResponse createCallbackUrl(Long applicationId, String name, String callbackUrl) throws RemoteException {
        PowerAuthPortServiceStub.CreateCallbackUrlRequest request = new PowerAuthPortServiceStub.CreateCallbackUrlRequest();
        request.setApplicationId(applicationId);
        request.setName(name);
        request.setCallbackUrl(callbackUrl);
        return this.createCallbackUrl(request);
    }

    /**
     * Get the response with list of callback URL objects.
     * @param request SOAP request object with application ID.
     * @return Response with the list of all callback URLs for given application.
     */
    public PowerAuthPortServiceStub.GetCallbackUrlListResponse getCallbackUrlList(PowerAuthPortServiceStub.GetCallbackUrlListRequest request) throws RemoteException {
        return clientStub.getCallbackUrlList(request);
    }

    /**
     * Get the list of callback URL objects.
     * @param applicationId Application ID.
     * @return List of all callback URLs for given application.
     */
    public List<PowerAuthPortServiceStub.CallbackUrlList_type0> getCallbackUrlList(Long applicationId) throws RemoteException {
        PowerAuthPortServiceStub.GetCallbackUrlListRequest request = new PowerAuthPortServiceStub.GetCallbackUrlListRequest();
        request.setApplicationId(applicationId);
        return Arrays.asList(getCallbackUrlList(request).getCallbackUrlList());
    }

    /**
     * Remove callback URL.
     * @param request Remove callback URL request.
     * @return Information about removal status.
     */
    public PowerAuthPortServiceStub.RemoveCallbackUrlResponse removeCallbackUrl(PowerAuthPortServiceStub.RemoveCallbackUrlRequest request) throws RemoteException {
        return clientStub.removeCallbackUrl(request);
    }

    /**
     * Remove callback URL.
     * @param callbackUrlId Callback URL ID.
     * @return Information about removal status.
     */
    public PowerAuthPortServiceStub.RemoveCallbackUrlResponse removeCallbackUrl(String callbackUrlId) throws RemoteException {
        PowerAuthPortServiceStub.RemoveCallbackUrlRequest request = new PowerAuthPortServiceStub.RemoveCallbackUrlRequest();
        request.setId(callbackUrlId);
        return removeCallbackUrl(request);
    }


}
