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

import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.ByteUtils;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.PqcKemKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.PqcKem;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecret;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyFactory;
import com.wultra.security.powerauth.crypto.lib.v4.model.*;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseHybrid;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Shared secret implementation for hybrid scheme with ECDHE on curve P-384 and ML-KEM-768.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SharedSecretHybrid implements SharedSecret<SharedSecretRequestHybrid, SharedSecretResponseHybrid, SharedSecretClientContextHybrid> {

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcKemKeyConvertor KEY_CONVERTOR_PQC = new PqcKemKeyConvertor();

    private static final PqcKem PQC_KEM = new PqcKem();

    @Override
    public SharedSecretAlgorithm getAlgorithm() {
        return SharedSecretAlgorithm.EC_P384_ML_L3;
    }

    @Override
    public RequestCryptogram generateRequestCryptogram() throws GenericCryptoException {
        try {
            final KeyPair ecClientEcKeyPair = KEY_GENERATOR.generateKeyPair(EcCurve.P384);
            final KeyPair pqcClientKeyPair = PQC_KEM.generateKeyPair();
            final byte[] ecPublicKeyRaw = KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, ecClientEcKeyPair.getPublic());
            final String ecPublicKeyBase64 = Base64.getEncoder().encodeToString(ecPublicKeyRaw);
            final byte[] pqcPublicKeyRaw = KEY_CONVERTOR_PQC.convertPublicKeyToBytes(pqcClientKeyPair.getPublic());
            final String pqcPublicKeyBase64 = Base64.getEncoder().encodeToString(pqcPublicKeyRaw);
            final SharedSecretRequestHybrid request = new SharedSecretRequestHybrid(ecPublicKeyBase64, pqcPublicKeyBase64);
            final SharedSecretClientContext clientContext = new SharedSecretClientContextHybrid(ecClientEcKeyPair.getPrivate(), pqcClientKeyPair.getPrivate());
            return new RequestCryptogram(request, clientContext);
        } catch (CryptoProviderException e) {
            throw new GenericCryptoException("Shared secret generation failed", e);
        }
    }

    @Override
    public ResponseCryptogram generateResponseCryptogram(SharedSecretRequestHybrid request) throws GenericCryptoException {
        if (request == null || request.getEcClientPublicKey() == null || request.getPqcEncapsulationKey() == null) {
            throw new GenericCryptoException("Invalid shared secret request");
        }
        try {
            final byte[] ecClientPublicKeyRaw = Base64.getDecoder().decode(request.getEcClientPublicKey());
            final PublicKey ecClientPublicKey = KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P384, ecClientPublicKeyRaw);
            final byte[] pqcClientPublicKeyRaw = Base64.getDecoder().decode(request.getPqcEncapsulationKey());
            final PublicKey pqcClientKemEncapsulationKey = KEY_CONVERTOR_PQC.convertBytesToPublicKey(pqcClientPublicKeyRaw);
            final KeyPair ecServerKeyPair = KEY_GENERATOR.generateKeyPair(EcCurve.P384);
            final SecretKey ecSharedKey = KEY_GENERATOR.computeSharedKey(ecServerKeyPair.getPrivate(), ecClientPublicKey, true);
            final SecretKeyWithEncapsulation pqcKeyWithEncaps = PQC_KEM.encapsulate(pqcClientKemEncapsulationKey);
            final byte[] ecSharedKeyBytes = KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(ecSharedKey);
            final byte[] pqcSharedKeyBytes = pqcKeyWithEncaps.getEncoded();
            final byte[] hybridKeyBytes = ByteUtils.concat(ecSharedKeyBytes, pqcSharedKeyBytes);
            final SecretKey hybridKey = KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(hybridKeyBytes);
            final SecretKey sharedSecret = KeyFactory.deriveKeySharedSecretHybrid(hybridKey);
            final byte[] ecServerPublicKey = KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, ecServerKeyPair.getPublic());
            final String ecServerPublicKeyBase64 = Base64.getEncoder().encodeToString(ecServerPublicKey);
            final String encapsBase64 = Base64.getEncoder().encodeToString(pqcKeyWithEncaps.getEncapsulation());
            final SharedSecretResponseHybrid serverResponse = new SharedSecretResponseHybrid(ecServerPublicKeyBase64, encapsBase64);
            return new ResponseCryptogram(serverResponse, sharedSecret);
        } catch (CryptoProviderException | InvalidKeySpecException | InvalidKeyException e) {
            throw new GenericCryptoException("Shared secret generation failed", e);
        }
    }

    @Override
    public SecretKey computeSharedSecret(SharedSecretClientContextHybrid clientContext, SharedSecretResponseHybrid serverResponse) throws GenericCryptoException {
        if (serverResponse == null || serverResponse.getEcServerPublicKey() == null || serverResponse.getPqcEncapsulation() == null) {
            throw new GenericCryptoException("Invalid shared secret request");
        }
        try {
            final byte[] ecServerPublicKeyRaw = Base64.getDecoder().decode(serverResponse.getEcServerPublicKey());
            final PublicKey ecServerPublicKey = KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P384, ecServerPublicKeyRaw);
            final byte[] pqcPqcKemCipherText = Base64.getDecoder().decode(serverResponse.getPqcEncapsulation());
            final PrivateKey ecClientPrivateKey = clientContext.getEcPrivateKey();
            final SecretKey ecSharedKey = KEY_GENERATOR.computeSharedKey(ecClientPrivateKey, ecServerPublicKey, true);
            final PrivateKey pqcClientDecapsKey = clientContext.getPqcKemDecapsulationKey();
            final SecretKey pqcSharedKey = PQC_KEM.decapsulate(pqcClientDecapsKey, pqcPqcKemCipherText);
            final byte[] ecSharedKeyBytes = KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(ecSharedKey);
            final byte[] pqcSharedKeyBytes = KEY_CONVERTOR_PQC.convertSharedSecretKeyToBytes(pqcSharedKey);
            final byte[] hybridKeyBytes = ByteUtils.concat(ecSharedKeyBytes, pqcSharedKeyBytes);
            final SecretKey hybridKey = KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(hybridKeyBytes);
            return KeyFactory.deriveKeySharedSecretHybrid(hybridKey);
        } catch (CryptoProviderException | InvalidKeySpecException | InvalidKeyException e) {
            throw new GenericCryptoException("Shared secret generation failed", e);
        }
    }

}
