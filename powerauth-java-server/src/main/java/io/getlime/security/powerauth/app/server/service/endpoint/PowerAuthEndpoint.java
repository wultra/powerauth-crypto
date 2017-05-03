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
package io.getlime.security.powerauth.app.server.service.endpoint;

import io.getlime.security.powerauth.*;
import io.getlime.security.powerauth.app.server.service.PowerAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;

/**
 * Class implementing the SOAP service end-point.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Endpoint
public class PowerAuthEndpoint {

    private static final String NAMESPACE_URI = "http://getlime.io/security/powerauth";

    private PowerAuthService powerAuthService;

    @Autowired
    public void setPowerAuthService(PowerAuthService powerAuthService) {
        this.powerAuthService = powerAuthService;
    }

    /**
     * Call {@link PowerAuthService#getSystemStatus(GetSystemStatusRequest)} method and
     * return the response.
     *
     * @param request Get system status request.
     * @return System status response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetSystemStatusRequest")
    @ResponsePayload
    public GetSystemStatusResponse getSystemStatus(@RequestPayload GetSystemStatusRequest request) throws Exception {
        return powerAuthService.getSystemStatus(request);
    }

    /**
     * Call {@link PowerAuthService#getErrorCodeList(GetErrorCodeListRequest)} method and
     * return the response.
     *
     * @param request Request for list of error codes indicating a language to be returned in.
     * @return Response with the list of error codes..
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetErrorCodeListRequest")
    @ResponsePayload
    public GetErrorCodeListResponse getErrorCodeList(@RequestPayload GetErrorCodeListRequest request) throws Exception {
        return powerAuthService.getErrorCodeList(request);
    }

    /**
     * Call {@link PowerAuthService#initActivation(InitActivationRequest)} method and
     * return the response.
     *
     * @param request Init activation request.
     * @return Init activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "InitActivationRequest")
    @ResponsePayload
    public InitActivationResponse initActivation(@RequestPayload InitActivationRequest request) throws Exception {
        return powerAuthService.initActivation(request);
    }

    /**
     * Call {@link PowerAuthService#prepareActivation(PrepareActivationRequest)} method and
     * return the response.
     *
     * @param request Prepare activation request.
     * @return Prepare activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "PrepareActivationRequest")
    @ResponsePayload
    public PrepareActivationResponse prepareActivation(@RequestPayload PrepareActivationRequest request) throws Exception {
        return powerAuthService.prepareActivation(request);
    }

    /**
     * Call {@link PowerAuthService#createActivation(CreateActivationRequest)} method and
     * return the response.
     *
     * @param request Create activation request.
     * @return Create activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateActivationRequest")
    @ResponsePayload
    public CreateActivationResponse createActivation(@RequestPayload CreateActivationRequest request) throws Exception {
        return powerAuthService.createActivation(request);
    }

    /**
     * Call {@link PowerAuthService#commitActivation(CommitActivationRequest)} method and
     * return the response.
     *
     * @param request Commit activation request.
     * @return Commit activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CommitActivationRequest")
    @ResponsePayload
    public CommitActivationResponse commitActivation(@RequestPayload CommitActivationRequest request) throws Exception {
        return powerAuthService.commitActivation(request);
    }

    /**
     * Call {@link PowerAuthService#getActivationStatus(GetActivationStatusRequest)} method and
     * return the response.
     *
     * @param request Activation status request.
     * @return Activation status response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetActivationStatusRequest")
    @ResponsePayload
    public GetActivationStatusResponse getActivationStatus(@RequestPayload GetActivationStatusRequest request) throws Exception {
        return powerAuthService.getActivationStatus(request);
    }

    /**
     * Call {@link PowerAuthService#removeActivation(RemoveActivationRequest)} method and
     * return the response.
     *
     * @param request Remove activation request.
     * @return Remove activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "RemoveActivationRequest")
    @ResponsePayload
    public RemoveActivationResponse removeActivation(@RequestPayload RemoveActivationRequest request) throws Exception {
        return powerAuthService.removeActivation(request);
    }

    /**
     * Call {@link PowerAuthService#getActivatioListForUser(GetActivationListForUserRequest)} method and
     * return the response.
     *
     * @param request Activation list request.
     * @return Activation list response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetActivationListForUserRequest")
    @ResponsePayload
    public GetActivationListForUserResponse getActivatioListForUser(@RequestPayload GetActivationListForUserRequest request) throws Exception {
        return powerAuthService.getActivatioListForUser(request);
    }

    /**
     * Call {@link PowerAuthService#verifySignature(VerifySignatureRequest)} method and
     * return the response.
     *
     * @param request Verify signature request.
     * @return Verify signature response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "VerifySignatureRequest")
    @ResponsePayload
    public VerifySignatureResponse verifySignature(@RequestPayload VerifySignatureRequest request) throws Exception {
        return powerAuthService.verifySignature(request);
    }

    /**
     * Call {@link PowerAuthService#vaultUnlock(VaultUnlockRequest)} method and
     * return the response.
     *
     * @param request Vault unlock request.
     * @return Vault unlock response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "VaultUnlockRequest")
    @ResponsePayload
    public VaultUnlockResponse vaultUnlock(@RequestPayload VaultUnlockRequest request) throws Exception {
        return powerAuthService.vaultUnlock(request);
    }

    /**
     * Call {@link PowerAuthService#generateE2EPersonalizedEncryptionKey(GetPersonalizedEncryptionKeyRequest)} method and
     * return the response.
     *
     * @param request E2E encryption key request.
     * @return E2E encryption key response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetPersonalizedEncryptionKeyRequest")
    @ResponsePayload
    public GetPersonalizedEncryptionKeyResponse generateE2EPersonalizedEncryptionKey(@RequestPayload GetPersonalizedEncryptionKeyRequest request) throws Exception {
        return powerAuthService.generateE2EPersonalizedEncryptionKey(request);
    }

    /**
     * Call {@link PowerAuthService#generateE2ENonPersonalizedEncryptionKey(GetNonPersonalizedEncryptionKeyRequest)} method and
     * return the response.
     *
     * @param request E2E encryption key request.
     * @return E2E encryption key response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetNonPersonalizedEncryptionKeyRequest")
    @ResponsePayload
    public GetNonPersonalizedEncryptionKeyResponse generateE2ENonPersonalizedEncryptionKey(@RequestPayload GetNonPersonalizedEncryptionKeyRequest request) throws Exception {
        return powerAuthService.generateE2ENonPersonalizedEncryptionKey(request);
    }

    /**
     * Call {@link PowerAuthService#verifyECDSASignature(VerifyECDSASignatureRequest)} method and
     * return the response.
     *
     * @param request Verify ECDSA signature request.
     * @return Verify ECDSA signature response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "VerifyECDSASignatureRequest")
    @ResponsePayload
    public VerifyECDSASignatureResponse verifySignature(@RequestPayload VerifyECDSASignatureRequest request) throws Exception {
        return powerAuthService.verifyECDSASignature(request);
    }

    /**
     * Call {@link PowerAuthService#getSignatureAuditLog(SignatureAuditRequest)} method and
     * return the response.
     *
     * @param request Signature audit request.
     * @return Signature audit response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "SignatureAuditRequest")
    @ResponsePayload
    public SignatureAuditResponse vaultUnlock(@RequestPayload SignatureAuditRequest request) throws Exception {
        return powerAuthService.getSignatureAuditLog(request);
    }

    /**
     * Call {@link PowerAuthService#blockActivation(BlockActivationRequest)} method and
     * return the response.
     *
     * @param request Block activation request.
     * @return Block activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "BlockActivationRequest")
    @ResponsePayload
    public BlockActivationResponse blockActivation(@RequestPayload BlockActivationRequest request) throws Exception {
        return powerAuthService.blockActivation(request);
    }

    /**
     * Call {@link PowerAuthService#unblockActivation(UnblockActivationRequest)} method and
     * return the response.
     *
     * @param request Unblock activation request.
     * @return Unblock activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "UnblockActivationRequest")
    @ResponsePayload
    public UnblockActivationResponse unblockActivation(@RequestPayload UnblockActivationRequest request) throws Exception {
        return powerAuthService.unblockActivation(request);
    }

    /**
     * Call {@link PowerAuthService#getApplicationList(GetApplicationListRequest)} method and
     * return the response.
     *
     * @param request Application list request.
     * @return Application list response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetApplicationListRequest")
    @ResponsePayload
    public GetApplicationListResponse getApplicationList(@RequestPayload GetApplicationListRequest request) throws Exception {
        return powerAuthService.getApplicationList(request);
    }

    /**
     * Call {@link PowerAuthService#getApplicationDetail(GetApplicationDetailRequest)} method and
     * return the response.
     *
     * @param request Application detail request.
     * @return Application detail response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetApplicationDetailRequest")
    @ResponsePayload
    public GetApplicationDetailResponse getApplicationDetail(@RequestPayload GetApplicationDetailRequest request) throws Exception {
        return powerAuthService.getApplicationDetail(request);
    }

    /**
     * Call {@link PowerAuthService#lookupApplicationByAppKey(LookupApplicationByAppKeyRequest)} method and
     * return the response.
     *
     * @param request Application lookup request.
     * @return Application lookup response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "LookupApplicationByAppKeyRequest")
    @ResponsePayload
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(@RequestPayload LookupApplicationByAppKeyRequest request) throws Exception {
        return powerAuthService.lookupApplicationByAppKey(request);
    }

    /**
     * Call {@link PowerAuthService#createApplication(CreateApplicationRequest)} method and
     * return the response.
     *
     * @param request Create application request.
     * @return Create application response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateApplicationRequest")
    @ResponsePayload
    public CreateApplicationResponse createApplication(@RequestPayload CreateApplicationRequest request) throws Exception {
        return powerAuthService.createApplication(request);
    }

    /**
     * Call {@link PowerAuthService#createApplicationVersion(CreateApplicationVersionRequest)} method and
     * return the response.
     *
     * @param request Create application version request.
     * @return Create application version response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateApplicationVersionRequest")
    @ResponsePayload
    public CreateApplicationVersionResponse createApplicationVersion(@RequestPayload CreateApplicationVersionRequest request) throws Exception {
        return powerAuthService.createApplicationVersion(request);
    }

    /**
     * Call {@link PowerAuthService#unsupportApplicationVersion(UnsupportApplicationVersionRequest)} method and
     * return the response.
     *
     * @param request Unsupport application version request.
     * @return Unsupport application version response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "UnsupportApplicationVersionRequest")
    @ResponsePayload
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(@RequestPayload UnsupportApplicationVersionRequest request) throws Exception {
        return powerAuthService.unsupportApplicationVersion(request);
    }

    /**
     * Call {@link PowerAuthService#supportApplicationVersion(SupportApplicationVersionRequest)} method and
     * return the response.
     *
     * @param request Support application version request.
     * @return Support application version response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "SupportApplicationVersionRequest")
    @ResponsePayload
    public SupportApplicationVersionResponse supportApplicationVersion(@RequestPayload SupportApplicationVersionRequest request) throws Exception {
        return powerAuthService.supportApplicationVersion(request);
    }

    /**
     * Call {@link PowerAuthService#createIntegration(CreateIntegrationRequest)} method and
     * return the response.
     *
     * @param request Create integration request.
     * @return Create integration response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateIntegrationRequest")
    @ResponsePayload
    public CreateIntegrationResponse createIntegration(@RequestPayload CreateIntegrationRequest request) throws Exception {
        return powerAuthService.createIntegration(request);
    }

    /**
     * Call {@link PowerAuthService#getIntegrationList(GetIntegrationListRequest)} method and
     * return the response.
     *
     * @param request Get integration list request.
     * @return Get integration list response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetIntegrationListRequest")
    @ResponsePayload
    public GetIntegrationListResponse getIntegrationList(@RequestPayload GetIntegrationListRequest request) throws Exception {
        return powerAuthService.getIntegrationList(request);
    }

    /**
     * Call {@link PowerAuthService#removeIntegration(RemoveIntegrationRequest)}  method and
     * return the response.
     *
     * @param request Remove integration request.
     * @return Remove integration response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "RemoveIntegrationRequest")
    @ResponsePayload
    public RemoveIntegrationResponse removeIntegration(@RequestPayload RemoveIntegrationRequest request) throws Exception {
        return powerAuthService.removeIntegration(request);
    }

    /**
     * Call {@link PowerAuthService#createCallbackUrl(CreateCallbackUrlRequest)} method and
     * return the response.
     *
     * @param request Create callback UR: request.
     * @return Create callback URL response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateCallbackUrlRequest")
    @ResponsePayload
    public CreateCallbackUrlResponse createCallbackUrl(@RequestPayload CreateCallbackUrlRequest request) throws Exception {
        return powerAuthService.createCallbackUrl(request);
    }

    /**
     * Call {@link PowerAuthService#getCallbackUrlList(GetCallbackUrlListRequest)}  method and
     * return the response.
     *
     * @param request Get callback URL list request.
     * @return Get callback URL list response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetCallbackUrlListRequest")
    @ResponsePayload
    public GetCallbackUrlListResponse getCallbackUrlList(@RequestPayload GetCallbackUrlListRequest request) throws Exception {
        return powerAuthService.getCallbackUrlList(request);
    }

    /**
     * Call {@link PowerAuthService#removeCallbackUrl(RemoveCallbackUrlRequest)} method and
     * return the response.
     *
     * @param request Remove callback URL request.
     * @return Remove callback URL response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "RemoveCallbackUrlRequest")
    @ResponsePayload
    public RemoveCallbackUrlResponse removeIntegration(@RequestPayload RemoveCallbackUrlRequest request) throws Exception {
        return powerAuthService.removeCallbackUrl(request);
    }

}
