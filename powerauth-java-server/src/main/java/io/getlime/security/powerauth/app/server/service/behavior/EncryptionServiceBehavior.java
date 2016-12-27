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
import io.getlime.security.powerauth.GetEncryptionKeyResponse;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.app.server.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.repository.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.util.model.ServiceError;
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

    private LocalizationProvider localizationProvider;

    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();

    @Autowired
    public EncryptionServiceBehavior(ActivationRepository activationRepository) {
        this.activationRepository = activationRepository;
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
    public GetEncryptionKeyResponse generateEncryptionKeyForActivation(String activationId, CryptoProviderUtil keyConversionUtilities) throws Exception {
        final ActivationRecordEntity activation = activationRepository.findFirstByActivationId(activationId);
        if (activation == null) {
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
        byte[] index = keyGenerator.generateRandomBytes(16);

        byte[] tmpBytes = new HMACHashUtilities().hash(index, masterTransportKeyData);
        byte[] derivedTransportKeyBytes = keyGenerator.convert32Bto16B(tmpBytes);

        String indexBase64 = BaseEncoding.base64().encode(index);
        String derivedTransportKeyBase64 = BaseEncoding.base64().encode(derivedTransportKeyBytes);

        GetEncryptionKeyResponse response = new GetEncryptionKeyResponse();
        response.setActivationId(activation.getActivationId());
        response.setEncryptionKey(derivedTransportKeyBase64);
        response.setEncryptionKeyIndex(indexBase64);
        return response;
    }

}
