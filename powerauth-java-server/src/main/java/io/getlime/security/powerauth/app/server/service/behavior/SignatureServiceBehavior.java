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

package io.getlime.security.powerauth.app.server.service.behavior;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.VerifySignatureResponse;
import io.getlime.security.powerauth.app.server.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.repository.ApplicationVersionRepository;
import io.getlime.security.powerauth.app.server.repository.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.repository.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.repository.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.service.util.ModelUtil;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.crypto.server.signature.PowerAuthServerSignature;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;

/**
 * Behavior class implementing the signature validation related processes. The class separates the
 * logics from the main service class.
 *
 * @author Petr Dvorak
 */
@Component
public class SignatureServiceBehavior {

    private ActivationRepository powerAuthRepository;

    private ApplicationVersionRepository applicationVersionRepository;

    private AuditingServiceBehavior auditingServiceBehavior;

    private CallbackUrlBehavior callbackUrlBehavior;

    @Autowired
    public SignatureServiceBehavior(ActivationRepository powerAuthRepository, ApplicationVersionRepository applicationVersionRepository) {
        this.powerAuthRepository = powerAuthRepository;
        this.applicationVersionRepository = applicationVersionRepository;
    }

    @Autowired
    public void setAuditingServiceBehavior(AuditingServiceBehavior auditingServiceBehavior) {
        this.auditingServiceBehavior = auditingServiceBehavior;
    }

    @Autowired
    public void setCallbackUrlBehavior(CallbackUrlBehavior callbackUrlBehavior) {
        this.callbackUrlBehavior = callbackUrlBehavior;
    }

    private final PowerAuthServerSignature powerAuthServerSignature = new PowerAuthServerSignature();
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();

    /**
     * Verify signature for given activation and provided data. Log every validation attempt in the audit log.
     *
     * @param activationId           Activation ID.
     * @param signatureType          Provided signature type.
     * @param signature              Provided signature.
     * @param dataString             String with data used to compute the signature.
     * @param applicationKey         Associated application key.
     * @param keyConversionUtilities Conversion utility class.
     * @return Response with the signature validation result object.
     * @throws UnsupportedEncodingException In case UTF-8 is not supported on the system.
     * @throws InvalidKeySpecException      In case invalid key is provided.
     * @throws InvalidKeyException          In case invalid key is provided.
     */
    public VerifySignatureResponse verifySignature(String activationId, String signatureType, String signature, String dataString, String applicationKey, CryptoProviderUtil keyConversionUtilities) throws UnsupportedEncodingException, InvalidKeySpecException, InvalidKeyException {
        // Prepare current timestamp in advance
        Date currentTimestamp = new Date();

        // Fetch related activation
        ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);

        // Only validate signature for existing ACTIVE activation records
        if (activation != null) {

            // Check the activation - application relationship and version support
            ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);

            if (applicationVersion == null || applicationVersion.getSupported() == false || applicationVersion.getApplication().getId() != activation.getApplication().getId()) {

                // Get the data and append application KEY in this case, just for auditing reasons
                byte[] data = (dataString + "&" + applicationKey).getBytes("UTF-8");

                // Increment the counter
                activation.setCounter(activation.getCounter() + 1);

                // Update failed attempts and block the activation, if necessary
                activation.setFailedAttempts(activation.getFailedAttempts() + 1);
                Long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
                if (remainingAttempts <= 0) {
                    activation.setActivationStatus(ActivationStatus.BLOCKED);
                }

                // Update the last used date
                activation.setTimestampLastUsed(currentTimestamp);

                // Save the activation
                powerAuthRepository.save(activation);

                auditingServiceBehavior.logSignatureAuditRecord(activation, signatureType, signature, data, false, "activation_invalid_application", currentTimestamp);

                // return the data
                VerifySignatureResponse response = new VerifySignatureResponse();
                response.setActivationId(activationId);
                response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.REMOVED));
                response.setRemainingAttempts(BigInteger.valueOf(0));
                response.setSignatureValid(false);
                response.setUserId("UNKNOWN");

                return response;
            }

            String applicationSecret = applicationVersion.getApplicationSecret();
            byte[] data = (dataString + "&" + applicationSecret).getBytes("UTF-8");

            if (activation.getActivationStatus() == ActivationStatus.ACTIVE) {

                // Get the server private and device public keys
                byte[] serverPrivateKeyBytes = BaseEncoding.base64().decode(activation.getServerPrivateKeyBase64());
                byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
                PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(serverPrivateKeyBytes);
                PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(devicePublicKeyBytes);

                // Compute the master secret key
                SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);

                // Get the signature keys according to the signature type
                List<SecretKey> signatureKeys = powerAuthServerKeyFactory.keysForSignatureType(signatureType, masterSecretKey);

                // Verify the signature with given lookahead
                boolean signatureValid = false;
                long ctr = activation.getCounter();
                long lowestValidCounter = ctr;
                for (long iterCtr = ctr; iterCtr < ctr + PowerAuthConfiguration.SIGNATURE_VALIDATION_LOOKAHEAD; iterCtr++) {
                    signatureValid = powerAuthServerSignature.verifySignatureForData(data, signature, signatureKeys, iterCtr);
                    if (signatureValid) {
                        // set the lowest valid counter and break at the lowest
                        // counter where signature validates
                        lowestValidCounter = iterCtr;
                        break;
                    }
                }
                if (signatureValid) {

                    // Set the activation record counter to the lowest counter
                    // (+1, since the client has incremented the counter)
                    activation.setCounter(lowestValidCounter + 1);

                    // Reset failed attempt count
                    activation.setFailedAttempts(0L);

                    // Update the last used date
                    activation.setTimestampLastUsed(currentTimestamp);

                    // Save the activation
                    powerAuthRepository.save(activation);

                    auditingServiceBehavior.logSignatureAuditRecord(activation, signatureType, signature, data, true, "signature_ok", currentTimestamp);

                    // return the data
                    VerifySignatureResponse response = new VerifySignatureResponse();
                    response.setActivationId(activationId);
                    response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.ACTIVE));
                    response.setRemainingAttempts(BigInteger.valueOf(activation.getMaxFailedAttempts()));
                    response.setSignatureValid(true);
                    response.setUserId(activation.getUserId());

                    return response;

                } else {

                    // Increment the activation record counter
                    activation.setCounter(activation.getCounter() + 1);

                    // Update failed attempts and block the activation, if
                    // necessary
                    activation.setFailedAttempts(activation.getFailedAttempts() + 1);
                    Long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
                    if (remainingAttempts <= 0) {
                        activation.setActivationStatus(ActivationStatus.BLOCKED);
                    }

                    // Update the last used date
                    activation.setTimestampLastUsed(currentTimestamp);

                    // Save the activation
                    powerAuthRepository.save(activation);

                    auditingServiceBehavior.logSignatureAuditRecord(activation, signatureType, signature, data, false, "signature_does_not_match", currentTimestamp);

                    // return the data
                    VerifySignatureResponse response = new VerifySignatureResponse();
                    response.setActivationId(activationId);
                    response.setActivationStatus(ModelUtil.toServiceStatus(activation.getActivationStatus()));
                    response.setRemainingAttempts(BigInteger.valueOf(remainingAttempts));
                    response.setSignatureValid(false);
                    response.setUserId(activation.getUserId());

                    return response;

                }

            } else {

                // Despite the fact activation is not in active state, increase
                // the counter
                activation.setCounter(activation.getCounter() + 1);

                // Update the last used date
                activation.setTimestampLastUsed(currentTimestamp);

                // Save the activation
                powerAuthRepository.save(activation);

                auditingServiceBehavior.logSignatureAuditRecord(activation, signatureType, signature, data, false, "activation_invalid_state", currentTimestamp);

                // return the data
                VerifySignatureResponse response = new VerifySignatureResponse();
                response.setActivationId(activationId);
                response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.REMOVED));
                response.setRemainingAttempts(BigInteger.valueOf(0));
                response.setSignatureValid(false);
                response.setUserId("UNKNOWN");

                return response;

            }

        } else { // Activation does not exist

            // return the data
            VerifySignatureResponse response = new VerifySignatureResponse();
            response.setActivationId(activationId);
            response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.REMOVED));
            response.setRemainingAttempts(BigInteger.valueOf(0));
            response.setSignatureValid(false);
            response.setUserId("UNKNOWN");

            return response;

        }
    }

}
