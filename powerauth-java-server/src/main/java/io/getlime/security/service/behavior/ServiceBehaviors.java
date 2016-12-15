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

package io.getlime.security.service.behavior;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Collection of all behaviors used by the PowerAuth 2.0 Server service.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Component
public class ServiceBehaviors {

    @Autowired
    private ActivationServiceBehavior activationServiceBehavior;

    @Autowired
    private ApplicationServiceBehavior applicationServiceBehavior;

    @Autowired
    private AuditingServiceBehavior auditingServiceBehavior;

    @Autowired
    private SignatureServiceBehavior signatureServiceBehavior;

    @Autowired
    private VaultUnlockServiceBehavior vaultUnlockServiceBehavior;

    @Autowired
    private EncryptionServiceBehavior encryptionServiceBehavior;

    @Autowired
    private IntegrationBehavior integrationBehavior;

    @Autowired
    private CallbackUrlBehavior callbackUrlBehavior;

    @Autowired
    private AsymmetricSignatureServiceBehavior asymmetricSignatureServiceBehavior;

    public ActivationServiceBehavior getActivationServiceBehavior() {
        return activationServiceBehavior;
    }

    public void setActivationServiceBehavior(ActivationServiceBehavior activationServiceBehavior) {
        this.activationServiceBehavior = activationServiceBehavior;
    }

    public ApplicationServiceBehavior getApplicationServiceBehavior() {
        return applicationServiceBehavior;
    }

    public void setApplicationServiceBehavior(ApplicationServiceBehavior applicationServiceBehavior) {
        this.applicationServiceBehavior = applicationServiceBehavior;
    }

    public AuditingServiceBehavior getAuditingServiceBehavior() {
        return auditingServiceBehavior;
    }

    public void setAuditingServiceBehavior(AuditingServiceBehavior auditingServiceBehavior) {
        this.auditingServiceBehavior = auditingServiceBehavior;
    }

    public SignatureServiceBehavior getSignatureServiceBehavior() {
        return signatureServiceBehavior;
    }

    public void setSignatureServiceBehavior(SignatureServiceBehavior signatureServiceBehavior) {
        this.signatureServiceBehavior = signatureServiceBehavior;
    }

    public VaultUnlockServiceBehavior getVaultUnlockServiceBehavior() {
        return vaultUnlockServiceBehavior;
    }

    public void setVaultUnlockServiceBehavior(VaultUnlockServiceBehavior vaultUnlockServiceBehavior) {
        this.vaultUnlockServiceBehavior = vaultUnlockServiceBehavior;
    }

    public EncryptionServiceBehavior getEncryptionServiceBehavior() {
        return encryptionServiceBehavior;
    }

    public void setEncryptionServiceBehavior(EncryptionServiceBehavior encryptionServiceBehavior) {
        this.encryptionServiceBehavior = encryptionServiceBehavior;
    }

    public IntegrationBehavior getIntegrationBehavior() {
        return integrationBehavior;
    }

    public void setIntegrationBehavior(IntegrationBehavior integrationBehavior) {
        this.integrationBehavior = integrationBehavior;
    }

    public CallbackUrlBehavior getCallbackUrlBehavior() {
        return callbackUrlBehavior;
    }

    public void setCallbackUrlBehavior(CallbackUrlBehavior callbackUrlBehavior) {
        this.callbackUrlBehavior = callbackUrlBehavior;
    }

    public AsymmetricSignatureServiceBehavior getAsymmetricSignatureServiceBehavior() {
        return asymmetricSignatureServiceBehavior;
    }

    public void setAsymmetricSignatureServiceBehavior(AsymmetricSignatureServiceBehavior asymmetricSignatureServiceBehavior) {
        this.asymmetricSignatureServiceBehavior = asymmetricSignatureServiceBehavior;
    }
}
