package io.getlime.security.service;

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

public interface PowerAuthService {
    
    public InitActivationResponse initActivation(InitActivationRequest request);
    
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request);
    
    public CommitActivationResponse commitActivation(CommitActivationRequest request);
    
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request);
    
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request);
    
    public GetActivationListForUserResponse getActivatioListForUser(GetActivationListForUserRequest request);
    
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request);
    
    public BlockActivationResponse blockActivation(BlockActivationRequest request);
    
    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request);
    
}
