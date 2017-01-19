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

package io.getlime.security.powerauth.rest.api.base.encryption;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.encryptor.NonPersonalizedEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.NonPersonalizedEncryptedMessage;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiRequest;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;

import java.io.IOException;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PowerAuthNonPersonalizedEncryptor {

    private NonPersonalizedEncryptor encryptor;

    ObjectMapper mapper = new ObjectMapper();

    public PowerAuthNonPersonalizedEncryptor(String applicationKeyBase64, String sessionKeyBytesBase64, String sessionIndexBase64, String ephemeralPublicKeyBase64) {
        byte[] applicationKey = BaseEncoding.base64().decode(applicationKeyBase64);
        byte[] sessionIndex = BaseEncoding.base64().decode(sessionIndexBase64);
        byte[] sessionKeyBytes = BaseEncoding.base64().decode(sessionKeyBytesBase64);
        byte[] ephemeralKeyBytes = BaseEncoding.base64().decode(ephemeralPublicKeyBase64);
        this.encryptor = new NonPersonalizedEncryptor(applicationKey, sessionKeyBytes, sessionIndex, ephemeralKeyBytes);
    }

    public PowerAuthApiResponse<NonPersonalizedEncryptedPayloadModel> encrypt(Object object) throws JsonProcessingException {
        if (object == null) {
            return null;
        }
        byte[] originalData = mapper.writeValueAsBytes(object);
        return this.encrypt(originalData);
    }

    public PowerAuthApiResponse<NonPersonalizedEncryptedPayloadModel> encrypt(byte[] originalData) {

        if (originalData == null) {
            return null;
        }

        NonPersonalizedEncryptedMessage message = encryptor.encrypt(originalData);

        if (message == null) { // this will happen only in case of an unlikely randomness error, or if keys are corrupted
            return null;
        }

        NonPersonalizedEncryptedPayloadModel responseObject = new NonPersonalizedEncryptedPayloadModel();
        responseObject.setApplicationKey(BaseEncoding.base64().encode(message.getApplicationKey()));
        responseObject.setEphemeralPublicKey(BaseEncoding.base64().encode(message.getEphemeralPublicKey()));
        responseObject.setSessionIndex(BaseEncoding.base64().encode(message.getSessionIndex()));
        responseObject.setAdHocIndex(BaseEncoding.base64().encode(message.getAdHocIndex()));
        responseObject.setMacIndex(BaseEncoding.base64().encode(message.getMacIndex()));
        responseObject.setNonce(BaseEncoding.base64().encode(message.getNonce()));
        responseObject.setMac(BaseEncoding.base64().encode(message.getMac()));
        responseObject.setEncryptedData(BaseEncoding.base64().encode(message.getEncryptedData()));

        return new PowerAuthApiResponse<>(
                PowerAuthApiResponse.Status.OK,
                PowerAuthApiResponse.Encryption.NON_PERSONALIZED,
                responseObject
        );
    }

    public byte[] decrypt(PowerAuthApiRequest<NonPersonalizedEncryptedPayloadModel> request) {

        if (request == null) {
            return null;
        }

        NonPersonalizedEncryptedPayloadModel requestObject = request.getRequestObject();

        if (requestObject == null) {
            return null;
        }

        NonPersonalizedEncryptedMessage message = new NonPersonalizedEncryptedMessage();
        message.setApplicationKey(BaseEncoding.base64().decode(requestObject.getApplicationKey()));
        message.setEphemeralPublicKey(BaseEncoding.base64().decode(requestObject.getEphemeralPublicKey()));
        message.setSessionIndex(BaseEncoding.base64().decode(requestObject.getSessionIndex()));
        message.setAdHocIndex(BaseEncoding.base64().decode(requestObject.getAdHocIndex()));
        message.setMacIndex(BaseEncoding.base64().decode(requestObject.getMacIndex()));
        message.setNonce(BaseEncoding.base64().decode(requestObject.getNonce()));
        message.setMac(BaseEncoding.base64().decode(requestObject.getMac()));
        message.setEncryptedData(BaseEncoding.base64().decode(requestObject.getEncryptedData()));

        return encryptor.decrypt(message);
    }

    public <T> T decrypt(PowerAuthApiRequest<NonPersonalizedEncryptedPayloadModel> request, Class<T> resultClass) throws IOException {
        byte[] result = this.decrypt(request);
        if (result == null) {
            return null;
        }
        return mapper.readValue(result, resultClass);
    }

}
