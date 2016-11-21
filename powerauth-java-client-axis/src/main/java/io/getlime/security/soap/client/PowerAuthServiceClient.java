/*
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.getlime.security.soap.client;


import io.getlime.powerauth.soap.*;

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

    public PowerAuthServiceClient() {
    }

    public PowerAuthServiceClient(PowerAuthPortServiceStub clientStub) {
        this.clientStub = clientStub;
    }

    public void setClientStub(PowerAuthPortServiceStub clientStub) {
        this.clientStub = clientStub;
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
     * @param request {@link PowerAuthPortServiceStub.GetSystemStatusRequest} instance
     * @return {@link PowerAuthPortServiceStub.GetSystemStatusResponse}
     */
    public PowerAuthPortServiceStub.GetSystemStatusResponse getSystemStatus(PowerAuthPortServiceStub.GetSystemStatusRequest request) throws RemoteException {
        return clientStub.getSystemStatus(request);
    }

    /**
     * Call the getSystemStatus method of the PowerAuth 2.0 Server SOAP interface.
     * @return {@link PowerAuthPortServiceStub.GetSystemStatusResponse}
     */
    public PowerAuthPortServiceStub.GetSystemStatusResponse getSystemStatus() throws RemoteException {
        PowerAuthPortServiceStub.GetSystemStatusRequest request = new PowerAuthPortServiceStub.GetSystemStatusRequest();
        return clientStub.getSystemStatus(request);
    }

    /**
     * Call the initActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link PowerAuthPortServiceStub.InitActivationRequest} instance
     * @return {@link PowerAuthPortServiceStub.InitActivationResponse}
     */
    public PowerAuthPortServiceStub.InitActivationResponse initActivation(PowerAuthPortServiceStub.InitActivationRequest request) throws RemoteException {
        return clientStub.initActivation(request);
    }

    /**
     * Call the initActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param userId User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @return {@link PowerAuthPortServiceStub.InitActivationResponse}
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
     * @return {@link PowerAuthPortServiceStub.InitActivationResponse}
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
     * @param request {@link PowerAuthPortServiceStub.PrepareActivationRequest} instance
     * @return {@link PowerAuthPortServiceStub.PrepareActivationResponse}
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
     * @return {@link PowerAuthPortServiceStub.PrepareActivationResponse}
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
     * Call the commitActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link PowerAuthPortServiceStub.CommitActivationRequest} instance
     * @return {@link PowerAuthPortServiceStub.CommitActivationResponse}
     */
    public PowerAuthPortServiceStub.CommitActivationResponse commitActivation(PowerAuthPortServiceStub.CommitActivationRequest request) throws RemoteException {
        return clientStub.commitActivation(request);
    }

    /**
     * Call the prepareActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID for activation to be committed.
     * @return {@link PowerAuthPortServiceStub.CommitActivationResponse}
     */
    public PowerAuthPortServiceStub.CommitActivationResponse commitActivation(String activationId) throws RemoteException {
        PowerAuthPortServiceStub.CommitActivationRequest request = new PowerAuthPortServiceStub.CommitActivationRequest();
        request.setActivationId(activationId);
        return this.commitActivation(request);
    }

    /**
     * Call the getActivationStatus method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link PowerAuthPortServiceStub.GetActivationStatusRequest} instance
     * @return {@link PowerAuthPortServiceStub.GetActivationStatusResponse}
     */
    public PowerAuthPortServiceStub.GetActivationStatusResponse getActivationStatus(PowerAuthPortServiceStub.GetActivationStatusRequest request) throws RemoteException {
        return clientStub.getActivationStatus(request);
    }

    /**
     * Call the getActivationStatus method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation Id to lookup information for.
     * @return {@link PowerAuthPortServiceStub.GetActivationStatusResponse}
     */
    public PowerAuthPortServiceStub.GetActivationStatusResponse getActivationStatus(String activationId) throws RemoteException {
        PowerAuthPortServiceStub.GetActivationStatusRequest request = new PowerAuthPortServiceStub.GetActivationStatusRequest();
        request.setActivationId(activationId);
        return this.getActivationStatus(request);
    }

    /**
     * Call the getActivationListForUser method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link PowerAuthPortServiceStub.GetActivationListForUserRequest} instance
     * @return {@link PowerAuthPortServiceStub.GetActivationListForUserResponse}
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
     * @param request {@link PowerAuthPortServiceStub.RemoveActivationRequest} instance.
     * @return {@link PowerAuthPortServiceStub.RemoveActivationResponse}
     */
    public PowerAuthPortServiceStub.RemoveActivationResponse removeActivation(PowerAuthPortServiceStub.RemoveActivationRequest request) throws RemoteException {
        return clientStub.removeActivation(request);
    }

    /**
     * Call the removeActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be removed.
     * @return {@link PowerAuthPortServiceStub.RemoveActivationResponse}
     */
    public PowerAuthPortServiceStub.RemoveActivationResponse removeActivation(String activationId) throws RemoteException {
        PowerAuthPortServiceStub.RemoveActivationRequest request = new PowerAuthPortServiceStub.RemoveActivationRequest();
        request.setActivationId(activationId);
        return this.removeActivation(request);
    }

    /**
     * Call the blockActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link PowerAuthPortServiceStub.BlockActivationRequest} instance.
     * @return {@link PowerAuthPortServiceStub.BlockActivationResponse}
     */
    public PowerAuthPortServiceStub.BlockActivationResponse blockActivation(PowerAuthPortServiceStub.BlockActivationRequest request) throws RemoteException {
        return clientStub.blockActivation(request);
    }

    /**
     * Call the blockActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be blocked.
     * @return {@link PowerAuthPortServiceStub.BlockActivationResponse}
     */
    public PowerAuthPortServiceStub.BlockActivationResponse blockActivation(String activationId) throws RemoteException {
        PowerAuthPortServiceStub.BlockActivationRequest request = new PowerAuthPortServiceStub.BlockActivationRequest();
        request.setActivationId(activationId);
        return this.blockActivation(request);
    }

    /**
     * Call the unblockActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link PowerAuthPortServiceStub.UnblockActivationRequest} instance.
     * @return {@link PowerAuthPortServiceStub.UnblockActivationResponse}
     */
    public PowerAuthPortServiceStub.UnblockActivationResponse unblockActivation(PowerAuthPortServiceStub.UnblockActivationRequest request) throws RemoteException {
        return clientStub.unblockActivation(request);
    }

    /**
     * Call the unblockActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be unblocked.
     * @return {@link PowerAuthPortServiceStub.UnblockActivationResponse}
     */
    public PowerAuthPortServiceStub.UnblockActivationResponse unblockActivation(String activationId) throws RemoteException {
        PowerAuthPortServiceStub.UnblockActivationRequest request = new PowerAuthPortServiceStub.UnblockActivationRequest();
        request.setActivationId(activationId);
        return this.unblockActivation(request);
    }

    /**
     * Call the vaultUnlock method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link PowerAuthPortServiceStub.VaultUnlockRequest} instance
     * @return {@link PowerAuthPortServiceStub.VaultUnlockResponse}
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
     * @return {@link PowerAuthPortServiceStub.VaultUnlockResponse}
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
     * @param request {@link PowerAuthPortServiceStub.VerifySignatureRequest} instance.
     * @return {@link PowerAuthPortServiceStub.VerifySignatureResponse}
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
     * @param request {@link PowerAuthPortServiceStub.VerifyECDSASignatureRequest} instance.
     * @return {@link PowerAuthPortServiceStub.VerifyECDSASignatureResponse}
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
     * Call the generateE2EEncryptionKey method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link PowerAuthPortServiceStub.GetEncryptionKeyRequest} instance.
     * @return {@link PowerAuthPortServiceStub.GetEncryptionKeyResponse}
     */
    public PowerAuthPortServiceStub.GetEncryptionKeyResponse generateE2EEncryptionKey(PowerAuthPortServiceStub.GetEncryptionKeyRequest request) throws RemoteException {
        return clientStub.getEncryptionKey(request);
    }

    /**
     * Call the generateE2EEncryptionKey method of the PowerAuth 2.0 Server SOAP interface and get
     * newly generated derived encryption key.
     * @param activationId Activation ID used for the key generation.
     * @return {@link PowerAuthPortServiceStub.GetEncryptionKeyResponse}
     */
    public PowerAuthPortServiceStub.GetEncryptionKeyResponse generateE2EEncryptionKey(String activationId) throws RemoteException {
        PowerAuthPortServiceStub.GetEncryptionKeyRequest request = new PowerAuthPortServiceStub.GetEncryptionKeyRequest();
        request.setActivationId(activationId);
        return this.generateE2EEncryptionKey(request);
    }

    /**
     * Call the getSignatureAuditLog method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link PowerAuthPortServiceStub.SignatureAuditRequest} instance.
     * @return {@link PowerAuthPortServiceStub.SignatureAuditResponse}
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
     * @return List of signature audit items {@link PowerAuthPortServiceStub.Items_type0}
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
     * @return List of signature audit items {@link PowerAuthPortServiceStub.Items_type0}
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
     * @param request {@link PowerAuthPortServiceStub.GetApplicationListRequest} instance.
     * @return {@link PowerAuthPortServiceStub.GetApplicationListResponse}
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
     * @param request {@link PowerAuthPortServiceStub.GetApplicationDetailRequest} instance.
     * @return {@link PowerAuthPortServiceStub.GetApplicationDetailResponse}
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
     * @param request {@link PowerAuthPortServiceStub.CreateApplicationRequest} instance.
     * @return {@link PowerAuthPortServiceStub.CreateApplicationResponse}
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
     * @param request {@link PowerAuthPortServiceStub.CreateApplicationVersionRequest} instance.
     * @return {@link PowerAuthPortServiceStub.CreateApplicationVersionResponse}
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
     * @param request {@link PowerAuthPortServiceStub.UnsupportApplicationVersionRequest} instance.
     * @return {@link PowerAuthPortServiceStub.UnsupportApplicationVersionResponse}
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
     * @param request {@link PowerAuthPortServiceStub.SupportApplicationVersionRequest} instance.
     * @return {@link PowerAuthPortServiceStub.SupportApplicationVersionResponse}
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


}
