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

    public GetActivationListForUserResponse getActivatioListForUser(GetActivationListForUserRequest request) throws Exception;

    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws Exception;

    public InitActivationResponse initActivation(InitActivationRequest request) throws Exception;

    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws Exception;

    public VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws Exception;

    public CommitActivationResponse commitActivation(CommitActivationRequest request) throws Exception;

    public RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws Exception;

    public BlockActivationResponse blockActivation(BlockActivationRequest request) throws Exception;

    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws Exception;

}
