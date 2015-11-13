package io.getlime.security.service.endpoint;

import io.getlime.security.powerauth.BlockActivationRequest;
import io.getlime.security.powerauth.BlockActivationResponse;
import io.getlime.security.powerauth.CommitActivationRequest;
import io.getlime.security.powerauth.CommitActivationResponse;
import io.getlime.security.powerauth.GetActivationListForUserRequest;
import io.getlime.security.powerauth.GetActivationListForUserResponse;
import io.getlime.security.powerauth.GetActivationStatusRequest;
import io.getlime.security.powerauth.GetActivationStatusResponse;
import io.getlime.security.powerauth.InitActivationRequest;
import io.getlime.security.powerauth.InitActivationResponse;
import io.getlime.security.powerauth.PrepareActivationRequest;
import io.getlime.security.powerauth.PrepareActivationResponse;
import io.getlime.security.powerauth.RemoveActivationRequest;
import io.getlime.security.powerauth.RemoveActivationResponse;
import io.getlime.security.powerauth.UnblockActivationRequest;
import io.getlime.security.powerauth.UnblockActivationResponse;
import io.getlime.security.powerauth.VerifySignatureRequest;
import io.getlime.security.powerauth.VerifySignatureResponse;
import io.getlime.security.service.PowerAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;

@Endpoint
public class PowerAuthEndpoint {

    private static final String NAMESPACE_URI = "http://getlime.io/security/powerauth";

    @Autowired
    private PowerAuthService powerAuthService;

    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "InitActivationRequest")
    @ResponsePayload
    public InitActivationResponse initActivation(@RequestPayload InitActivationRequest request) throws Exception {
        return powerAuthService.initActivation(request);
    }

    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "PrepareActivationRequest")
    @ResponsePayload
    public PrepareActivationResponse prepareActivation(@RequestPayload PrepareActivationRequest request) throws Exception {
        return powerAuthService.prepareActivation(request);
    }

    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CommitActivationRequest")
    @ResponsePayload
    public CommitActivationResponse commitActivation(@RequestPayload CommitActivationRequest request) throws Exception {
        return powerAuthService.commitActivation(request);
    }

    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetActivationStatusRequest")
    @ResponsePayload
    public GetActivationStatusResponse getActivationStatus(@RequestPayload GetActivationStatusRequest request) throws Exception {
        return powerAuthService.getActivationStatus(request);
    }

    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "RemoveActivationRequest")
    @ResponsePayload
    public RemoveActivationResponse removeActivation(@RequestPayload RemoveActivationRequest request) throws Exception {
        return powerAuthService.removeActivation(request);
    }

    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetActivationListForUserRequest")
    @ResponsePayload
    public GetActivationListForUserResponse getActivatioListForUser(@RequestPayload GetActivationListForUserRequest request) throws Exception {
        return powerAuthService.getActivatioListForUser(request);
    }

    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "VerifySignatureRequest")
    @ResponsePayload
    public VerifySignatureResponse verifySignature(@RequestPayload VerifySignatureRequest request) throws Exception {
        return powerAuthService.verifySignature(request);
    }

    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "BlockActivationRequest")
    @ResponsePayload
    public BlockActivationResponse blockActivation(@RequestPayload BlockActivationRequest request) throws Exception {
        return powerAuthService.blockActivation(request);
    }

    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "UnblockActivationRequest")
    @ResponsePayload
    public UnblockActivationResponse unblockActivation(@RequestPayload UnblockActivationRequest request) throws Exception {
        return powerAuthService.unblockActivation(request);
    }

}
