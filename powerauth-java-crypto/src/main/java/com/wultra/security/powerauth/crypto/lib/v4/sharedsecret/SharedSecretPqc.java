/*
 * PowerAuth Crypto Library
 * Copyright 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.lib.v4.sharedsecret;

import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.PqcKemKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.PqcKem;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecret;
import com.wultra.security.powerauth.crypto.lib.v4.model.SharedSecretClientContextPqc;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestPqc;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponsePqc;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Shared secret implementation for hybrid scheme with ECDHE on curve P-384 and ML-KEM-768.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SharedSecretPqc implements SharedSecret<SharedSecretRequestPqc, SharedSecretResponsePqc, SharedSecretClientContextPqc> {

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final PqcKemKeyConvertor KEY_CONVERTOR_PQC = new PqcKemKeyConvertor();

    private static final PqcKem PQC_KEM = new PqcKem();

    @Override
    public SharedSecretAlgorithm getAlgorithm() {
        return SharedSecretAlgorithm.EC_P384_ML_L3;
    }

    @Override
    public RequestCryptogram generateRequestCryptogram() throws GenericCryptoException {
        final KeyPair pqcClientKeyPair = PQC_KEM.generateKeyPair();
        final byte[] pqcPublicKeyRaw = KEY_CONVERTOR_PQC.convertPublicKeyToBytes(pqcClientKeyPair.getPublic());
        final String pqcPublicKeyBase64 = Base64.getEncoder().encodeToString(pqcPublicKeyRaw);
        final SharedSecretRequestPqc request = new SharedSecretRequestPqc(pqcPublicKeyBase64);
        final SharedSecretClientContextPqc clientContext = new SharedSecretClientContextPqc(pqcClientKeyPair.getPrivate());
        return new RequestCryptogram(request, clientContext);
    }

    @Override
    public ResponseCryptogram generateResponseCryptogram(SharedSecretRequestPqc request) throws GenericCryptoException {
        if (request == null || request.getPqcEncapsulationKey() == null) {
            throw new GenericCryptoException("Invalid shared secret request");
        }
        final byte[] pqcClientPublicKeyRaw = Base64.getDecoder().decode(request.getPqcEncapsulationKey());
        final PublicKey pqcClientKemEncapsulationKey = KEY_CONVERTOR_PQC.convertBytesToPublicKey(pqcClientPublicKeyRaw);
        final SecretKeyWithEncapsulation pqcKeyWithEncaps = PQC_KEM.encapsulate(pqcClientKemEncapsulationKey);
        final SecretKey pqcSecretKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(pqcKeyWithEncaps.getEncoded());
        final String pqcSharedSecret = Base64.getEncoder().encodeToString(pqcKeyWithEncaps.getEncapsulation());
        final SharedSecretResponsePqc serverResponse = new SharedSecretResponsePqc(pqcSharedSecret);
        return new ResponseCryptogram(serverResponse, pqcSecretKey);
    }

    @Override
    public SecretKey computeSharedSecret(SharedSecretClientContextPqc clientContext, SharedSecretResponsePqc serverResponse) throws GenericCryptoException {
        if (serverResponse == null || serverResponse.getPqcCiphertext() == null) {
            throw new GenericCryptoException("Invalid shared secret request");
        }
        final byte[] pqcPqcKemCipherText = Base64.getDecoder().decode(serverResponse.getPqcCiphertext());
        final PrivateKey pqcClientDecapsKey = clientContext.getPqcKemDecapsulationKey();
        return PQC_KEM.decapsulate(pqcClientDecapsKey, pqcPqcKemCipherText);
    }

}
