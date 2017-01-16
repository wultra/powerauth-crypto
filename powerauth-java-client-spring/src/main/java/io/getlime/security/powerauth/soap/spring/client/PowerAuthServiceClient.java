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

package io.getlime.security.powerauth.soap.spring.client;

import io.getlime.powerauth.soap.*;
import io.getlime.powerauth.soap.GetActivationListForUserResponse.Activations;
import io.getlime.powerauth.soap.SignatureAuditResponse.Items;
import org.springframework.ws.client.core.support.WebServiceGatewaySupport;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

/**
 * Class implementing a PowerAuth SOAP service client based on provided WSDL
 * service description.
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthServiceClient extends WebServiceGatewaySupport {

    /**
     * Convert date to XMLGregorianCalendar
     * @param date Date to be converted.
     * @return A new instance of {@link XMLGregorianCalendar}.
     * @throws DatatypeConfigurationException
     */
    private XMLGregorianCalendar calendarWithDate(Date date) {
        try {
            GregorianCalendar c = new GregorianCalendar();
            c.setTime(date);
            return DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
        } catch (DatatypeConfigurationException e) {
            // Unless there is a terrible configuration error, this should not happen
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Call the getSystemStatus method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link GetSystemStatusRequest} instance
     * @return {@link GetSystemStatusResponse}
     */
    public GetSystemStatusResponse getSystemStatus(GetSystemStatusRequest request) {
        return (GetSystemStatusResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the getSystemStatus method of the PowerAuth 2.0 Server SOAP interface.
     * @return {@link GetSystemStatusResponse}
     */
    public GetSystemStatusResponse getSystemStatus() {
        GetSystemStatusRequest request = new GetSystemStatusRequest();
        return (GetSystemStatusResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the initActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link InitActivationRequest} instance
     * @return {@link InitActivationResponse}
     */
    public InitActivationResponse initActivation(InitActivationRequest request) {
        return (InitActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the initActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param userId User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @return {@link InitActivationResponse}
     */
    public InitActivationResponse initActivation(String userId, Long applicationId) {
        return this.initActivation(userId, applicationId, null, null);
    }

    /**
     * Call the initActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param userId User ID for which a new CREATED activation should be created.
     * @param applicationId Application ID for which a new CREATED activation should be created.
     * @param maxFailureCount How many failed attempts should be allowed for this activation.
     * @param timestampActivationExpire Timestamp until when the activation can be committed.
     * @return {@link InitActivationResponse}
     */
    public InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire) {
        InitActivationRequest request = new InitActivationRequest();
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
     * @param request {@link PrepareActivationRequest} instance
     * @return {@link PrepareActivationResponse}
     */
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) {
        return (PrepareActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
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
     * @return {@link PrepareActivationResponse}
     */
    public PrepareActivationResponse prepareActivation(String activationIdShort, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationKey, String applicationSignature) {
        PrepareActivationRequest request = new PrepareActivationRequest();
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
    public CreateActivationResponse createActivation(CreateActivationRequest request) {
        return (CreateActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
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
     * @return {@link io.getlime.powerauth.soap.CreateActivationResponse}
     */
    public CreateActivationResponse createActivation(String applicationKey, String userId, String identity, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) {
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
     * @param ephemeralPublicKey
     * @param extras Additional, application specific information.
     * @return {@link io.getlime.powerauth.soap.CreateActivationResponse}
     */
    public CreateActivationResponse createActivation(String applicationKey, String userId, Long maxFailureCount, Date timestampActivationExpire, String identity, String activationOtp, String activationName, String activationNonce, String ephemeralPublicKey, String cDevicePublicKey, String extras, String applicationSignature) {
        CreateActivationRequest request = new CreateActivationRequest();
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
     * @param request {@link CommitActivationRequest} instance
     * @return {@link CommitActivationResponse}
     */
    public CommitActivationResponse commitActivation(CommitActivationRequest request) {
        return (CommitActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the prepareActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID for activation to be commited.
     * @return {@link CommitActivationResponse}
     */
    public CommitActivationResponse commitActivation(String activationId) {
        CommitActivationRequest request = new CommitActivationRequest();
        request.setActivationId(activationId);
        return this.commitActivation(request);
    }

    /**
     * Call the getActivationStatus method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link GetActivationStatusRequest} instance
     * @return {@link GetActivationStatusResponse}
     */
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) {
        return (GetActivationStatusResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the getActivationStatus method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation Id to lookup information for.
     * @return {@link GetActivationStatusResponse}
     */
    public GetActivationStatusResponse getActivationStatus(String activationId) {
        GetActivationStatusRequest request = new GetActivationStatusRequest();
        request.setActivationId(activationId);
        return this.getActivationStatus(request);
    }

    /**
     * Call the getActivationListForUser method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link GetActivationListForUserRequest} instance
     * @return {@link GetActivationListForUserResponse}
     */
    public GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) {
        return (GetActivationListForUserResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the getActivationListForUser method of the PowerAuth 2.0 Server SOAP interface.
     * @param userId User ID to fetch the activations for.
     * @return List of activation instances for given user.
     */
    public List<Activations> getActivationListForUser(String userId) {
        GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId(userId);
        return this.getActivationListForUser(request).getActivations();
    }

    /**
     * Call the removeActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link RemoveActivationRequest} instance.
     * @return {@link RemoveActivationResponse}
     */
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request) {
        return (RemoveActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the removeActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be removed.
     * @return {@link RemoveActivationResponse}
     */
    public RemoveActivationResponse removeActivation(String activationId) {
        RemoveActivationRequest request = new RemoveActivationRequest();
        request.setActivationId(activationId);
        return this.removeActivation(request);
    }

    /**
     * Call the blockActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link BlockActivationRequest} instance.
     * @return {@link BlockActivationResponse}
     */
    public BlockActivationResponse blockActivation(BlockActivationRequest request) {
        return (BlockActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the blockActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be blocked.
     * @return {@link BlockActivationResponse}
     */
    public BlockActivationResponse blockActivation(String activationId) {
        BlockActivationRequest request = new BlockActivationRequest();
        request.setActivationId(activationId);
        return this.blockActivation(request);
    }

    /**
     * Call the unblockActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link UnblockActivationRequest} instance.
     * @return {@link UnblockActivationResponse}
     */
    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) {
        return (UnblockActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the unblockActivation method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be unblocked.
     * @return {@link UnblockActivationResponse}
     */
    public UnblockActivationResponse unblockActivation(String activationId) {
        UnblockActivationRequest request = new UnblockActivationRequest();
        request.setActivationId(activationId);
        return this.unblockActivation(request);
    }

    /**
     * Call the vaultUnlock method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link VaultUnlockRequest} instance
     * @return {@link VaultUnlockResponse}
     */
    public VaultUnlockResponse unlockVault(VaultUnlockRequest request) {
        return (VaultUnlockResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the vaultUnlock method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation Id of an activation to be used for authentication.
     * @param applicationKey Application Key of an application related to the activation.
     * @param data Data to be signed encoded in format as specified by PowerAuth 2.0 data normalization.
     * @param signature Vault opening request signature.
     * @param signatureType Vault opening request signature type.
     * @return {@link VaultUnlockResponse}
     */
    public VaultUnlockResponse unlockVault(String activationId, String applicationKey, String data, String signature, String signatureType) {
        VaultUnlockRequest request = new VaultUnlockRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setData(data);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        return this.unlockVault(request);
    }

    /**
     * Call the verifySignature method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link VerifySignatureRequest} instance.
     * @return {@link VerifySignatureResponse}
     */
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request) {
        return (VerifySignatureResponse) getWebServiceTemplate().marshalSendAndReceive(request);
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
    public VerifySignatureResponse verifySignature(String activationId, String applicationKey, String data, String signature, String signatureType) {
        VerifySignatureRequest request = new VerifySignatureRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setData(data);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        return this.verifySignature(request);
    }

    /**
     * Call the verifyECDSASignature method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link VerifyECDSASignatureRequest} instance.
     * @return {@link VerifyECDSASignatureResponse}
     */
    public VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) {
        return (VerifyECDSASignatureResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the verifyECDSASignature method of the PowerAuth 2.0 Server SOAP interface.
     * @param activationId Activation ID of activation to be used for authentication.
     * @param data Data that were signed by ECDSA algorithm.
     * @param signature Request signature.
     * @return Verify ECDSA signature and return SOAP response with the verification results.
     */
    public VerifyECDSASignatureResponse verifyECDSASignature(String activationId, String data, String signature) {
        VerifyECDSASignatureRequest request = new VerifyECDSASignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        return this.verifyECDSASignature(request);
    }

    /**
     * Call the generatePersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link GetPersonalizedEncryptionKeyRequest} instance.
     * @return {@link GetPersonalizedEncryptionKeyResponse}
     */
    public GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(GetPersonalizedEncryptionKeyRequest request) {
        return (GetPersonalizedEncryptionKeyResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the generatePersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server SOAP interface and get
     * newly generated derived encryption key.
     * @param activationId Activation ID used for the key generation.
     * @return {@link GetPersonalizedEncryptionKeyResponse}
     */
    public GetPersonalizedEncryptionKeyResponse generatePersonalizedE2EEncryptionKey(String activationId, String sessionIndex) {
        GetPersonalizedEncryptionKeyRequest request = new GetPersonalizedEncryptionKeyRequest();
        request.setActivationId(activationId);
        request.setSessionIndex(sessionIndex);
        return this.generatePersonalizedE2EEncryptionKey(request);
    }

    /**
     * Call the generateNonPersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link GetNonPersonalizedEncryptionKeyRequest} instance.
     * @return {@link GetNonPersonalizedEncryptionKeyResponse}
     */
    public GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(GetNonPersonalizedEncryptionKeyRequest request) {
        return (GetNonPersonalizedEncryptionKeyResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the generateNonPersonalizedE2EEncryptionKey method of the PowerAuth 2.0 Server SOAP interface and get
     * newly generated derived encryption key.
     * @param applicationKey Application key of application used for the key generation.
     * @return {@link GetNonPersonalizedEncryptionKeyResponse}
     */
    public GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedE2EEncryptionKey(String applicationKey, String ephemeralPublicKeyBase64, String sessionIndex) {
        GetNonPersonalizedEncryptionKeyRequest request = new GetNonPersonalizedEncryptionKeyRequest();
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKeyBase64);
        request.setSessionIndex(sessionIndex);
        return this.generateNonPersonalizedE2EEncryptionKey(request);
    }

    /**
     * Call the getSignatureAuditLog method of the PowerAuth 2.0 Server SOAP interface.
     * @param request {@link SignatureAuditRequest} instance.
     * @return {@link SignatureAuditResponse}
     */
    public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) {
        return (SignatureAuditResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Call the verifySignature method of the PowerAuth 2.0 Server SOAP interface and get
     * signature audit log for all application of a given user.
     * @param userId User ID to query the audit log against.
     * @param startingDate Limit the results to given starting date (= "newer than")
     * @param endingDate Limit the results to given ending date (= "older than")
     * @return List of signature audit items {@link Items}
     */
    public List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) {
        SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId(userId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return this.getSignatureAuditLog(request).getItems();
    }

    /**
     * Call the verifySignature method of the PowerAuth 2.0 Server SOAP interface and get
     * signature audit log for a single application.
     * @param userId User ID to query the audit log against.
     * @param applicationId Application ID to query the audit log against.
     * @param startingDate Limit the results to given starting date (= "newer than")
     * @param endingDate Limit the results to given ending date (= "older than")
     * @return List of signature audit items {@link Items}
     */
    public List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Long applicationId, Date startingDate, Date endingDate) {
        SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setTimestampFrom(calendarWithDate(startingDate));
        request.setTimestampTo(calendarWithDate(endingDate));
        return this.getSignatureAuditLog(request).getItems();
    }

    /**
     * Get the list of all applications that are registered in PowerAuth 2.0 Server.
     * @param request {@link GetApplicationListRequest} instance.
     * @return {@link GetApplicationListResponse}
     */
    public GetApplicationListResponse getApplicationList(GetApplicationListRequest request) {
        return (GetApplicationListResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Get the list of all applications that are registered in PowerAuth 2.0 Server.
     * @return List of applications.
     */
    public List<GetApplicationListResponse.Applications> getApplicationList() {
        return this.getApplicationList(new GetApplicationListRequest()).getApplications();
    }

    /**
     * Return the detail of given application, including all application versions.
     * @param request {@link GetApplicationDetailRequest} instance.
     * @return {@link GetApplicationDetailResponse}
     */
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) {
        return (GetApplicationDetailResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Get the detail of an application with given ID, including the version list.
     * @param applicationId ID of an application to fetch.
     * @return Application with given ID, including the version list.
     */
    public GetApplicationDetailResponse getApplicationDetail(Long applicationId) {
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(applicationId);
        return this.getApplicationDetail(request);
    }

    /**
     * Create a new application with given name.
     * @param request {@link CreateApplicationRequest} instance.
     * @return {@link CreateApplicationResponse}
     */
    public CreateApplicationResponse createApplication(CreateApplicationRequest request) {
        return (CreateApplicationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Create a new application with given name.
     * @param name Name of the new application.
     * @return Application with a given name.
     */
    public CreateApplicationResponse createApplication(String name) {
        CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationName(name);
        return this.createApplication(request);
    }

    /**
     * Create a version with a given name for an application with given ID.
     * @param request {@link CreateApplicationVersionRequest} instance.
     * @return {@link CreateApplicationVersionResponse}
     */
    public CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) {
        return (CreateApplicationVersionResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Create a version with a given name for an application with given ID.
     * @param applicationId ID of an application to create a version for.
     * @param versionName Name of the version. The value should follow some well received conventions (such as "1.0.3", for example).
     * @return A new version with a given name and application key / secret.
     */
    public CreateApplicationVersionResponse createApplicationVersion(Long applicationId, String versionName) {
        CreateApplicationVersionRequest request = new CreateApplicationVersionRequest();
        request.setApplicationId(applicationId);
        request.setApplicationVersionName(versionName);
        return this.createApplicationVersion(request);
    }

    /**
     * Cancel the support for a given application version.
     * @param request {@link UnsupportApplicationVersionRequest} instance.
     * @return {@link UnsupportApplicationVersionResponse}
     */
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) {
        return (UnsupportApplicationVersionResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Cancel the support for a given application version.
     * @param versionId Version to be unsupported.
     * @return Information about success / failure.
     */
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(Long versionId) {
        UnsupportApplicationVersionRequest request = new UnsupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.unsupportApplicationVersion(request);
    }

    /**
     * Renew the support for a given application version.
     * @param request {@link SupportApplicationVersionRequest} instance.
     * @return {@link SupportApplicationVersionResponse}
     */
    public SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) {
        return (SupportApplicationVersionResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Renew the support for a given application version.
     * @param versionId Version to be supported again.
     * @return Information about success / failure.
     */
    public SupportApplicationVersionResponse supportApplicationVersion(Long versionId) {
        SupportApplicationVersionRequest request = new SupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.supportApplicationVersion(request);
    }

    /**
     * Create a new integration with given name.
     * @param request Request specifying the integration name.
     * @return New integration information.
     */
    public CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) {
        return (CreateIntegrationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Create a new integration with given name.
     * @param name Integration name.
     * @return New integration information.
     */
    public CreateIntegrationResponse createIntegration(String name) {
        CreateIntegrationRequest request = new CreateIntegrationRequest();
        request.setName(name);
        return this.createIntegration(request);
    }

    /**
     * Get the list of integrations.
     * @param request SOAP request object.
     * @return List of integrations.
     */
    public GetIntegrationListResponse getIntegrationList(GetIntegrationListRequest request) {
        return (GetIntegrationListResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Get the list of integrations.
     * @return List of integrations.
     */
    public List<GetIntegrationListResponse.Items> getIntegrationList() {
        return this.getIntegrationList(new GetIntegrationListRequest()).getItems();
    }

    /**
     * Remove integration with given ID.
     * @param request SOAP object with integration ID to be removed.
     * @return Removal status.
     */
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) {
        return (RemoveIntegrationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Remove integration with given ID.
     * @param id ID of integration to be removed.
     * @return Removal status.
     */
    public RemoveIntegrationResponse removeIntegration(String id) {
        RemoveIntegrationRequest request = new RemoveIntegrationRequest();
        request.setId(id);
        return this.removeIntegration(request);
    }

    /**
     * Create a new callback URL with given request object.
     * @param request SOAP request object with callback URL details.
     * @return Information about new callback URL object.
     */
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) {
        return (CreateCallbackUrlResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Create a new callback URL with given parameters.
     * @param applicationId Application ID.
     * @param name Callback URL display name.
     * @param callbackUrl Callback URL value.
     * @return Information about new callback URL object.
     */
    public CreateCallbackUrlResponse createCallbackUrl(Long applicationId, String name, String callbackUrl) {
        CreateCallbackUrlRequest request = new CreateCallbackUrlRequest();
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
    public GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) {
        return (GetCallbackUrlListResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Get the list of callback URL objects.
     * @param applicationId Application ID.
     * @return List of all callback URLs for given application.
     */
    public List<GetCallbackUrlListResponse.CallbackUrlList> getCallbackUrlList(Long applicationId) {
        GetCallbackUrlListRequest request = new GetCallbackUrlListRequest();
        request.setApplicationId(applicationId);
        return getCallbackUrlList(request).getCallbackUrlList();
    }

    /**
     * Remove callback URL.
     * @param request Remove callback URL request.
     * @return Information about removal status.
     */
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) {
        return (RemoveCallbackUrlResponse) getWebServiceTemplate().marshalSendAndReceive(request);
    }

    /**
     * Remove callback URL.
     * @param callbackUrlId Callback URL ID.
     * @return Information about removal status.
     */
    public RemoveCallbackUrlResponse removeCallbackUrl(String callbackUrlId) {
        RemoveCallbackUrlRequest request = new RemoveCallbackUrlRequest();
        request.setId(callbackUrlId);
        return removeCallbackUrl(request);
    }

}
