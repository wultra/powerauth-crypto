/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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
import io.getlime.security.powerauth.SignatureAuditRequest;
import io.getlime.security.powerauth.SignatureAuditResponse;
import io.getlime.security.powerauth.UnblockActivationRequest;
import io.getlime.security.powerauth.UnblockActivationResponse;
import io.getlime.security.powerauth.VaultUnlockRequest;
import io.getlime.security.powerauth.VaultUnlockResponse;
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
    
    public VaultUnlockResponse vaultUnlock(VaultUnlockRequest request) throws Exception;
    
    public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws Exception;

}
