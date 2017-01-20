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
import io.getlime.security.powerauth.GetNonPersonalizedEncryptionKeyResponse;
import io.getlime.security.powerauth.GetPersonalizedEncryptionKeyResponse;
import io.getlime.security.powerauth.app.server.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.repository.ApplicationVersionRepository;
import io.getlime.security.powerauth.app.server.repository.MasterKeyPairRepository;
import io.getlime.security.powerauth.app.server.repository.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.repository.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.repository.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.repository.model.entity.MasterKeyPairEntity;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.util.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Behavior class implementing the end-to-end encryption related processes. The
 * class separates the logic from the main service class.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Component
public class EncryptionServiceBehavior {

    private ActivationRepository activationRepository;
    private MasterKeyPairRepository masterKeyPairRepository;
    private ApplicationVersionRepository applicationVersionRepository;

    private LocalizationProvider localizationProvider;

    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();

    @Autowired
    public EncryptionServiceBehavior(ActivationRepository activationRepository, MasterKeyPairRepository masterKeyPairRepository, ApplicationVersionRepository applicationVersionRepository) {
        this.activationRepository = activationRepository;
        this.masterKeyPairRepository = masterKeyPairRepository;
        this.applicationVersionRepository = applicationVersionRepository;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    /**
     * This method generates a derived transport key for the purpose of end-to-end encryption.
     * The response contains a derived key and index used to deduce it.
     * @param activationId Activation that is supposed to use encryption key.
     * @param keyConversionUtilities Key conversion utility class.
     * @return Response with a generated encryption key details.
     * @throws Exception In activation with given ID was not found or other business logic error.
     */
    public GetPersonalizedEncryptionKeyResponse generateEncryptionKeyForActivation(String activationId, String sessionIndex, CryptoProviderUtil keyConversionUtilities) throws Exception {
        final ActivationRecordEntity activation = activationRepository.findFirstByActivationId(activationId);

        // If there is no such activation or activation is not active, return error
        if (activation == null || !ActivationStatus.ACTIVE.equals(activation.getActivationStatus())) {
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }

        String devicePublicKeyBase64 = activation.getDevicePublicKeyBase64();
        String serverPrivateKeyBase64 = activation.getServerPrivateKeyBase64();
        PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(BaseEncoding.base64().decode(devicePublicKeyBase64));
        PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(BaseEncoding.base64().decode(serverPrivateKeyBase64));

        SecretKey masterKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
        SecretKey masterTransportKey = powerAuthServerKeyFactory.generateServerTransportKey(masterKey);
        byte[] masterTransportKeyData = keyConversionUtilities.convertSharedSecretKeyToBytes(masterTransportKey);

        KeyGenerator keyGenerator = new KeyGenerator();

        // Use provided index or generate own, if not provided.
        byte[] sessionIndexBytes = null;
        if (sessionIndex != null) {
            sessionIndexBytes = BaseEncoding.base64().decode(sessionIndex);
        }
        byte[] index;
        if (sessionIndexBytes == null || sessionIndexBytes.length != 16) {
            index = keyGenerator.generateRandomBytes(16);
        } else {
            index = sessionIndexBytes;
        }

        byte[] tmpBytes = new HMACHashUtilities().hash(index, masterTransportKeyData);
        byte[] derivedTransportKeyBytes = keyGenerator.convert32Bto16B(tmpBytes);

        String indexBase64 = BaseEncoding.base64().encode(index);
        String derivedTransportKeyBase64 = BaseEncoding.base64().encode(derivedTransportKeyBytes);

        GetPersonalizedEncryptionKeyResponse response = new GetPersonalizedEncryptionKeyResponse();
        response.setActivationId(activation.getActivationId());
        response.setEncryptionKey(derivedTransportKeyBase64);
        response.setEncryptionKeyIndex(indexBase64);
        return response;
    }

    /**
     * This method generates a derived transport key for the purpose of end-to-end encryption.
     * The response contains a derived key and index used to deduce it.
     * @param applicationKey Application that is supposed to use encryption key.
     * @param keyConversionUtilities Key conversion utility class.
     * @return Response with a generated encryption key details.
     * @throws Exception In activation with given ID was not found or other business logic error.
     */
    public GetNonPersonalizedEncryptionKeyResponse generateNonPersonalizedEncryptionKeyForApplication(String applicationKey, String sessionIndexBase64, String ephemeralPublicKeyBase64, CryptoProviderUtil keyConversionUtilities) throws Exception {

        ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);

        if (applicationVersion == null || !applicationVersion.getSupported()) {
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_APPLICATION_ID);
        }

        MasterKeyPairEntity keypair = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationVersion.getApplication().getId());
        if (keypair == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
        }

        byte[] ephemeralKeyBytes = BaseEncoding.base64().decode(ephemeralPublicKeyBase64);
        PublicKey ephemeralPublicKey = keyConversionUtilities.convertBytesToPublicKey(ephemeralKeyBytes);
        if (ephemeralPublicKey == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        }

        String masterPrivateKeyBase64 = keypair.getMasterKeyPrivateBase64();
        PrivateKey masterPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(BaseEncoding.base64().decode(masterPrivateKeyBase64));

        SecretKey masterKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(masterPrivateKey, ephemeralPublicKey);
        byte[] masterTransportKeyData = keyConversionUtilities.convertSharedSecretKeyToBytes(masterKey);

        KeyGenerator keyGenerator = new KeyGenerator();

        // Use provided index or generate own, if not provided.
        byte[] sessionIndexBytes = null;
        if (sessionIndexBase64 != null) {
            sessionIndexBytes = BaseEncoding.base64().decode(sessionIndexBase64);
        }
        byte[] index;
        if (sessionIndexBytes == null || sessionIndexBytes.length != 16) {
            index = keyGenerator.generateRandomBytes(16);
        } else {
            index = sessionIndexBytes;
        }

        byte[] tmpBytes = new HMACHashUtilities().hash(index, masterTransportKeyData);
        byte[] derivedTransportKeyBytes = keyGenerator.convert32Bto16B(tmpBytes);

        String indexBase64 = BaseEncoding.base64().encode(index);
        String derivedTransportKeyBase64 = BaseEncoding.base64().encode(derivedTransportKeyBytes);

        GetNonPersonalizedEncryptionKeyResponse response = new GetNonPersonalizedEncryptionKeyResponse();
        response.setApplicationKey(applicationKey);
        response.setApplicationId(applicationVersion.getApplication().getId());
        response.setEncryptionKey(derivedTransportKeyBase64);
        response.setEncryptionKeyIndex(indexBase64);
        response.setEphemeralPublicKey(ephemeralPublicKeyBase64);
        return response;
    }

}
