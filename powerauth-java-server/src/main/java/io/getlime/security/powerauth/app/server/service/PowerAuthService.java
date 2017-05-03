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
package io.getlime.security.powerauth.app.server.service;

import io.getlime.security.powerauth.*;

/**
 * Interface containing all methods that are published by the PowerAuth 2.0 Server
 * instance. These methods are then used to publish both SOAP and REST interface.
 *
 * @author Petr Dvorak.
 */
public interface PowerAuthService {

    /**
     * Get PowerAuth 2.0 Server system status.
     *
     * @param request Empty object.
     * @return System status.
     * @throws Exception In case of a business logic error.
     */
    GetSystemStatusResponse getSystemStatus(GetSystemStatusRequest request) throws Exception;

    /**
     * Get activations for a given user.
     *
     * @param request Activation list request object.
     * @return Activation list.
     * @throws Exception In case of a business logic error.
     */
    GetActivationListForUserResponse getActivatioListForUser(GetActivationListForUserRequest request) throws Exception;

    /**
     * Get activation status for given activation ID.
     *
     * @param request Activation status request object.
     * @return Activation status.
     * @throws Exception In case of a business logic error.
     */
    GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws Exception;

    /**
     * Get the list of error codes for given language.
     *
     * @param request Error code list request object.
     * @return Error code list.
     * @throws Exception In case of a business logic error.
     */
    GetErrorCodeListResponse getErrorCodeList(GetErrorCodeListRequest request) throws Exception;

    /**
     * Initiate a new activation for a given application and user ID. The new activation record is in
     * CREATED state after calling this method.
     *
     * @param request Init activation request object.
     * @return Activation init data.
     * @throws Exception In case of a business logic error.
     */
    InitActivationResponse initActivation(InitActivationRequest request) throws Exception;

    /**
     * Receive a PowerAuth 2.0 Client public key and return own PowerAuth 2.0 Server public key. The
     * activation with provided ID is in OTP_USED state after calling this method.
     *
     * @param request Prepare activation request object.
     * @return Prepare activation response.
     * @throws Exception In case of a business logic error.
     */
    PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws Exception;

    /**
     * Create a new activation in OTP_USED state, without the InitActivation / PrepareActivation cycle.
     * This method receives a PowerAuth 2.0 Client public key and returns own PowerAuth 2.0 Server public key.
     * The activation with is in OTP_USED state after calling this method.
     *
     * Note: This method should be used in case of activation performed directly, without the external
     * master front end application.
     *
     * @param request Create activation request object.
     * @return Create activation response.
     * @throws Exception In case of a business logic error.
     */
    CreateActivationResponse createActivation(CreateActivationRequest request) throws Exception;

    /**
     * Verify signature against provided data using activation with given ID. Each call to this method
     * increments a counter associated with an activation with given ID. In case too many failed
     * verification attempts occur (max. fail count is a property of an activation, default is 5),
     * activation is moved to BLOCKED state. In case a successful verification occurs, the fail counter
     * is reset back to zero.
     *
     * @param request Verify signature request object.
     * @return Signature verification response.
     * @throws Exception In case of a business logic error.
     */
    VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws Exception;

    /**
     * Commit a created activation. Only activations in OTP_USED state can be committed - in case activation
     * is in other state, exception is raised. In case of successful call of this method, activation with
     * provided ID is in ACTIVE state.
     *
     * @param request Activation commit request object.
     * @return Activation commit response.
     * @throws Exception In case of a business logic error.
     */
    CommitActivationResponse commitActivation(CommitActivationRequest request) throws Exception;

    /**
     * Remove activation with given ID - change it's status to REMOVED. Activations in any state can be removed.
     *
     * @param request Activation remove request object.
     * @return Activation remove response.
     * @throws Exception In case of a business logic error.
     */
    RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws Exception;

    /**
     * Block activation with given ID. Activation moves to BLOCKED state, only activations in ACTIVE state
     * can be blocked. Attempt to block an activation in incorrect state results in exception.
     *
     * @param request Block activation request object.
     * @return Block activation response.
     * @throws Exception In case of a business logic error.
     */
    BlockActivationResponse blockActivation(BlockActivationRequest request) throws Exception;

    /**
     * Unblock activation with given ID. Activation moves to ACTIVE state, only activations in BLOCKED state
     * can be blocked. Attempt to unblock an activation in incorrect state results in exception.
     *
     * @param request Unblock activation request object.
     * @return Unblock activation response.
     * @throws Exception In case of a business logic error.
     */
    UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws Exception;

    /**
     * Return the data for the vault unlock request. Part of the vault unlock process is performing a signature
     * validation - the rules for blocking activation and counter increment are therefore similar as for the
     * {@link PowerAuthService#verifySignature(VerifySignatureRequest)} method. For vaultUnlock, however,
     * counter is incremented by 2 - one for signature validation, second for the transport key derivation.
     *
     * @param request Vault unlock request object.
     * @return Vault unlock response.
     * @throws Exception In case of a business logic error.
     */
    VaultUnlockResponse vaultUnlock(VaultUnlockRequest request) throws Exception;

    /**
     * Generate an activation specific transport key with given index for the purpose of personalized end-to-end encryption.
     * @param request Request with an activation ID and optional session index.
     * @return Response with derived transport key and its session index.
     * @throws Exception In case of a business logic error.
     */
    GetPersonalizedEncryptionKeyResponse generateE2EPersonalizedEncryptionKey(GetPersonalizedEncryptionKeyRequest request) throws Exception;

    /**
     * Generate an application specific transport key with given index for the purpose of non-personalized end-to-end encryption.
     * @param request Request with application ID and optional session index.
     * @return Response with derived transport key and its session index.
     * @throws Exception In case of a business logic error.
     */
    GetNonPersonalizedEncryptionKeyResponse generateE2ENonPersonalizedEncryptionKey(GetNonPersonalizedEncryptionKeyRequest request) throws Exception;

    /**
     * Validate incoming ECDSA signature for provided data using a public device key associated with given activation.
     * @param request Request for signature validation.
     * @return Response with the signature validation status.
     * @throws Exception In case of a business logic error.
     */
    VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) throws Exception;

    /**
     * Get records from the signature audit log.
     *
     * @param request Signature audit log request.
     * @return Signature audit log response.
     * @throws Exception In case of a business logic error.
     */
    SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws Exception;

    /**
     * Get all applications in the system.
     *
     * @param request Application list request object.
     * @return Application list response.
     * @throws Exception In case of a business logic error.
     */
    GetApplicationListResponse getApplicationList(GetApplicationListRequest request) throws Exception;

    /**
     * Get application detail, including application version list.
     *
     * @param request Application detail request object.
     * @return Application detail response.
     * @throws Exception In case of a business logic error.
     */
    GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws Exception;

    /**
     * Get application detail, including application version list, based on the version app key.
     *
     * @param request Request object with version app key.
     * @return Application detail response.
     * @throws Exception In case of a business logic error.
     */
    LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) throws Exception;

    /**
     * Create a new application with given name. Master key pair and default application version is automatically
     * generated when calling this method.
     *
     * @param request Create application request.
     * @return Created application information response.
     * @throws Exception In case of a business logic error.
     */
    CreateApplicationResponse createApplication(CreateApplicationRequest request) throws Exception;

    /**
     * Create a new application version with given name. Each application version has its own APPLICATION_KEY
     * and APPLICATION_SECRET values.
     *
     * @param request Application version create request object.
     * @return Application version create response.
     * @throws Exception In case of a business logic error.
     */
    CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) throws Exception;

    /**
     * Unsupport an application version. If an application is unsupported, it's APPLICATION_KEY and APPLICATION_SECRET
     * cannot be used for computing a signature.
     *
     * @param request Unsupport application version request.
     * @return Unsupport application version response.
     * @throws Exception In case of a business logic error.
     */
    UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) throws Exception;

    /**
     * Support an application version. If an application is supported, it's APPLICATION_KEY and APPLICATION_SECRET
     * can be used for computing a signature.
     *
     * @param request Support application version request.
     * @return Support application version response.
     * @throws Exception In case of a business logic error.
     */
    SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) throws Exception;

    /**
     * Create a new credentials for integration with given name. Automatically generates appropriate credentials.
     * @param request Request with integration name.
     * @return Newly created integration details.
     * @throws Exception In case of a business logic error.
     */
    CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) throws Exception;

    /**
     * Get the list of currently present integrations.
     * @param request SOAP method request.
     * @return List of currently present integrations.
     * @throws Exception In case of a business logic error.
     */
    GetIntegrationListResponse getIntegrationList(GetIntegrationListRequest request) throws Exception;

    /**
     * Remove integration with given ID.
     * @param request Request with integration ID.
     * @return Removal status information.
     * @throws Exception In case of a business logic error.
     */
    RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) throws Exception;

    /**
     * Create a new callback URL for given application.
     * @param request Request with application ID and callback URL parameters.
     * @return New callback URL information.
     * @throws Exception In case of a business logic error.
     */
    CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws Exception;

    /**
     * Get the list of all callback URLs for given application.
     * @param request Request with application ID.
     * @return List of all callback URLs for given applications, ordered by name alphabetically.
     * @throws Exception In case of a business logic error.
     */
    GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) throws Exception;

    /**
     * Remove callback URL with given ID.
     * @param request Request with callback URL with given ID.
     * @return  Removal status information.
     * @throws Exception In case of a business logic error.
     */
    RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) throws Exception;

}
