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
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviors;
import io.getlime.security.powerauth.app.server.service.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.util.ModelUtil;
import io.getlime.security.powerauth.app.server.service.util.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.security.InvalidKeyException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Default implementation of the PowerAuth 2.0 Server service.
 * The implementation of this service is divided into "behaviors"
 * responsible for individual processes.
 *
 * @author Petr Dvorak
 */
@Component
public class PowerAuthServiceImpl implements PowerAuthService {

    private PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    private ServiceBehaviors behavior;

    private LocalizationProvider localizationProvider;

    @Autowired
    public void setPowerAuthServiceConfiguration(PowerAuthServiceConfiguration powerAuthServiceConfiguration) {
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
    }

    @Autowired
    public void setBehavior(ServiceBehaviors behavior) {
        this.behavior = behavior;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    private final CryptoProviderUtil keyConversionUtilities = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

    static {
        Security.addProvider(new BouncyCastleProvider());
        PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());
    }

    @Override
    public GetSystemStatusResponse getSystemStatus(GetSystemStatusRequest request) throws Exception {
        GetSystemStatusResponse response = new GetSystemStatusResponse();
        response.setStatus("OK");
        response.setApplicationName(powerAuthServiceConfiguration.getApplicationName());
        response.setApplicationDisplayName(powerAuthServiceConfiguration.getApplicationDisplayName());
        response.setApplicationEnvironment(powerAuthServiceConfiguration.getApplicationEnvironment());
        response.setTimestamp(ModelUtil.calendarWithDate(new Date()));
        return response;
    }

    @Override
    public GetErrorCodeListResponse getErrorCodeList(GetErrorCodeListRequest request) throws Exception {
        String language = request.getLanguage();
        // Check if the language is valid ISO language, use EN as default
        if (Arrays.binarySearch(Locale.getISOLanguages(), language) < 0) {
            language = Locale.ENGLISH.getLanguage();
        }
        Locale locale = new Locale(language);
        GetErrorCodeListResponse response = new GetErrorCodeListResponse();
        List<String> errorCodeList = ServiceError.allCodes();
        for (String errorCode : errorCodeList) {
            GetErrorCodeListResponse.Errors error = new GetErrorCodeListResponse.Errors();
            error.setCode(errorCode);
            error.setValue(localizationProvider.getLocalizedErrorMessage(errorCode, locale));
            response.getErrors().add(error);
        }
        return response;
    }

    @Override
    @Transactional
    public GetActivationListForUserResponse getActivatioListForUser(GetActivationListForUserRequest request) throws Exception {
        try {
            String userId = request.getUserId();
            Long applicationId = request.getApplicationId();
            return behavior.getActivationServiceBehavior().getActivationList(applicationId, userId);
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            return behavior.getActivationServiceBehavior().getActivationStatus(activationId, keyConversionUtilities);
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }

    }

    @Override
    @Transactional
    public InitActivationResponse initActivation(InitActivationRequest request) throws Exception {
        try {
            String userId = request.getUserId();
            Long applicationId = request.getApplicationId();
            Long maxFailedCount = request.getMaxFailureCount();
            Date activationExpireTimestamp = ModelUtil.dateWithCalendar(request.getTimestampActivationExpire());
            return behavior.getActivationServiceBehavior().initActivation(applicationId, userId, maxFailedCount, activationExpireTimestamp, keyConversionUtilities);
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        }
    }

    @Override
    @Transactional
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws Exception {
        try {
            // Get request parameters
            String activationIdShort = request.getActivationIdShort();
            String activationNonceBase64 = request.getActivationNonce();
            String cDevicePublicKeyBase64 = request.getEncryptedDevicePublicKey();
            String activationName = request.getActivationName();
            String ephemeralPublicKey = request.getEphemeralPublicKey();
            String applicationKey = request.getApplicationKey();
            String applicationSignature = request.getApplicationSignature();
            String extras = request.getExtras();
            return behavior.getActivationServiceBehavior().prepareActivation(activationIdShort, activationNonceBase64, ephemeralPublicKey, cDevicePublicKeyBase64, activationName, extras, applicationKey, applicationSignature, keyConversionUtilities);
        } catch (IllegalArgumentException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public CreateActivationResponse createActivation(CreateActivationRequest request) throws Exception {
        try {
            // Get request parameters
            String applicationKey = request.getApplicationKey();
            String userId = request.getUserId();
            Long maxFailedCount = request.getMaxFailureCount();
            Date activationExpireTimestamp = ModelUtil.dateWithCalendar(request.getTimestampActivationExpire());
            String identity = request.getIdentity();
            String activationOtp = request.getActivationOtp();
            String activationNonceBase64 = request.getActivationNonce();
            String cDevicePublicKeyBase64 = request.getEncryptedDevicePublicKey();
            String activationName = request.getActivationName();
            String ephemeralPublicKey = request.getEphemeralPublicKey();
            String applicationSignature = request.getApplicationSignature();
            String extras = request.getExtras();
            return behavior.getActivationServiceBehavior().createActivation(
                    applicationKey,
                    userId,
                    maxFailedCount,
                    activationExpireTimestamp,
                    identity,
                    activationOtp,
                    activationNonceBase64,
                    ephemeralPublicKey,
                    cDevicePublicKeyBase64,
                    activationName,
                    extras,
                    applicationSignature,
                    keyConversionUtilities
          );
        } catch (IllegalArgumentException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    private VerifySignatureResponse verifySignatureImplNonTransaction(VerifySignatureRequest request) throws Exception {

        // Get request data
        String activationId = request.getActivationId();
        String applicationKey = request.getApplicationKey();
        String dataString = request.getData();
        String signature = request.getSignature();
        String signatureType = request.getSignatureType().toLowerCase();

        return behavior.getSignatureServiceBehavior().verifySignature(activationId, signatureType, signature, dataString, applicationKey, keyConversionUtilities);

    }

    @Override
    @Transactional
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws Exception {
        try {
            return this.verifySignatureImplNonTransaction(request);
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public CommitActivationResponse commitActivation(CommitActivationRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            return behavior.getActivationServiceBehavior().commitActivation(activationId);
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            return behavior.getActivationServiceBehavior().removeActivation(activationId);
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public BlockActivationResponse blockActivation(BlockActivationRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            return behavior.getActivationServiceBehavior().blockActivation(activationId);
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            return behavior.getActivationServiceBehavior().unblockActivation(activationId);
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }

    }

    @Override
    @Transactional
    public VaultUnlockResponse vaultUnlock(VaultUnlockRequest request) throws Exception {
        try {

            // Get request data
            String activationId = request.getActivationId();
            String applicationKey = request.getApplicationKey();
            String signature = request.getSignature();
            String signatureType = request.getSignatureType().toLowerCase();
            String data = request.getData();

            // Reject 1FA signatures.
            if (signatureType.equals(PowerAuthSignatureTypes.BIOMETRY.toString())
                    || signatureType.equals(PowerAuthSignatureTypes.KNOWLEDGE.toString())
                    || signatureType.equals(PowerAuthSignatureTypes.POSSESSION.toString())) {
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_SIGNATURE);
            }

            // Verify the signature
            VerifySignatureRequest verifySignatureRequest = new VerifySignatureRequest();
            verifySignatureRequest.setActivationId(activationId);
            verifySignatureRequest.setApplicationKey(applicationKey);
            verifySignatureRequest.setData(data);
            verifySignatureRequest.setSignature(signature);
            verifySignatureRequest.setSignatureType(signatureType);
            VerifySignatureResponse verifySignatureResponse = this.verifySignatureImplNonTransaction(verifySignatureRequest);

            return behavior.getVaultUnlockServiceBehavior().unlockVault(activationId, verifySignatureResponse.isSignatureValid(), keyConversionUtilities);
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public GetPersonalizedEncryptionKeyResponse generateE2EPersonalizedEncryptionKey(GetPersonalizedEncryptionKeyRequest request) throws Exception {
        return behavior.getEncryptionServiceBehavior().generateEncryptionKeyForActivation(
                request.getActivationId(),
                request.getSessionIndex(),
                keyConversionUtilities
        );
    }

    @Override
    @Transactional
    public GetNonPersonalizedEncryptionKeyResponse generateE2ENonPersonalizedEncryptionKey(GetNonPersonalizedEncryptionKeyRequest request) throws Exception {
        return behavior.getEncryptionServiceBehavior().generateNonPersonalizedEncryptionKeyForApplication(
                request.getApplicationKey(),
                request.getSessionIndex(),
                request.getEphemeralPublicKey(),
                keyConversionUtilities
        );
    }

    @Override
    @Transactional
    public VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            String signedData = request.getData();
            String signature  = request.getSignature();
            boolean matches = behavior.getAsymmetricSignatureServiceBehavior().verifyECDSASignature(activationId, signedData, signature, keyConversionUtilities);
            VerifyECDSASignatureResponse response = new VerifyECDSASignatureResponse();
            response.setSignatureValid(matches);
            return response;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws Exception {
        try {

            String userId = request.getUserId();
            Long applicationId = request.getApplicationId();
            Date startingDate = ModelUtil.dateWithCalendar(request.getTimestampFrom());
            Date endingDate = ModelUtil.dateWithCalendar(request.getTimestampTo());

            return behavior.getAuditingServiceBehavior().getSignatureAuditLog(userId, applicationId, startingDate, endingDate);

        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }

    }

    @Override
    @Transactional
    public GetApplicationListResponse getApplicationList(GetApplicationListRequest request) throws Exception {
        return behavior.getApplicationServiceBehavior().getApplicationList();
    }

    @Override
    @Transactional
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws Exception {
        return behavior.getApplicationServiceBehavior().getApplicationDetail(request.getApplicationId());
    }

    @Override
    @Transactional
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) throws Exception {
        try {
            return behavior.getApplicationServiceBehavior().lookupApplicationByAppKey(request.getApplicationKey());
        } catch (Throwable t) {
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_APPLICATION_ID);
        }
    }

    @Override
    @Transactional
    public CreateApplicationResponse createApplication(CreateApplicationRequest request) throws Exception {
        return behavior.getApplicationServiceBehavior().createApplication(request.getApplicationName(), keyConversionUtilities);
    }

    @Override
    @Transactional
    public CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) throws Exception {
        return behavior.getApplicationServiceBehavior().createApplicationVersion(request.getApplicationId(), request.getApplicationVersionName());
    }

    @Override
    @Transactional
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) throws Exception {
        return behavior.getApplicationServiceBehavior().unsupportApplicationVersion(request.getApplicationVersionId());
    }

    @Override
    @Transactional
    public SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) throws Exception {
        return behavior.getApplicationServiceBehavior().supportApplicationVersion(request.getApplicationVersionId());
    }

    @Override
    @Transactional
    public CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) throws Exception {
        return behavior.getIntegrationBehavior().createIntegration(request);
    }

    @Override
    @Transactional
    public GetIntegrationListResponse getIntegrationList(GetIntegrationListRequest request) throws Exception {
        return behavior.getIntegrationBehavior().getIntegrationList(request);
    }

    @Override
    @Transactional
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) throws Exception {
        return behavior.getIntegrationBehavior().removeIntegration(request);
    }

    @Override
    @Transactional
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws Exception {
        return behavior.getCallbackUrlBehavior().createCallbackUrl(request);
    }

    @Override
    @Transactional
    public GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) throws Exception {
        return behavior.getCallbackUrlBehavior().getCallbackUrlList(request);
    }

    @Override
    @Transactional
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) throws Exception {
        return behavior.getCallbackUrlBehavior().removeIntegration(request);
    }

}
