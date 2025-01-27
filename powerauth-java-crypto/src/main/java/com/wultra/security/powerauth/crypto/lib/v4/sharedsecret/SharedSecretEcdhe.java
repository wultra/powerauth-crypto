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
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecret;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.Kdf;
import com.wultra.security.powerauth.crypto.lib.v4.model.*;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Shared secret implementation for ECDHE on curve P-384.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SharedSecretEcdhe implements SharedSecret<SharedSecretRequestEcdhe, SharedSecretResponseEcdhe, SharedSecretClientContextEcdhe> {

    private static final long SHARED_SECRET_DERIVATION_INDEX = 20_000L;

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    @Override
    public SharedSecretAlgorithm getAlgorithm() {
        return SharedSecretAlgorithm.EC_P384;
    }

    @Override
    public RequestCryptogram generateRequestCryptogram() throws Exception {
        final KeyPair ecClientKeyPair = KEY_GENERATOR.generateKeyPair(EcCurve.P384);
        final byte[] ecPublicKeyRaw = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P384, ecClientKeyPair.getPublic());
        final String ecPublicKeyBase64 = Base64.getEncoder().encodeToString(ecPublicKeyRaw);
        final SharedSecretRequestEcdhe request = new SharedSecretRequestEcdhe(ecPublicKeyBase64);
        final SharedSecretClientContext clientContext = new SharedSecretClientContextEcdhe(ecClientKeyPair.getPrivate());
        return new RequestCryptogram(request, clientContext);
    }

    @Override
    public ResponseCryptogram generateResponseCryptogram(SharedSecretRequestEcdhe request) throws Exception {
        final byte[] ecClientPublicKeyRaw = Base64.getDecoder().decode(request.getEcdhe());
        final PublicKey ecClientPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P384, ecClientPublicKeyRaw);
        final KeyPair ecServerKeyPair = KEY_GENERATOR.generateKeyPair(EcCurve.P384);
        final SecretKey ecSharedKey = KEY_GENERATOR.computeSharedKey(ecServerKeyPair.getPrivate(), ecClientPublicKey, true);
        final SecretKey sharedSecret = Kdf.derive(ecSharedKey, SHARED_SECRET_DERIVATION_INDEX, 32, null);
        final byte[] ecServerPublicKey = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P384, ecServerKeyPair.getPublic());
        final String ecServerPublicKeyBase64 = Base64.getEncoder().encodeToString(ecServerPublicKey);
        final SharedSecretResponseEcdhe serverResponse = new SharedSecretResponseEcdhe(ecServerPublicKeyBase64);
        return new ResponseCryptogram(serverResponse, sharedSecret);
    }

    @Override
    public SecretKey computeSharedSecret(SharedSecretClientContextEcdhe sharedSecretClientContextEcdhe, SharedSecretResponseEcdhe sharedSecretResponseEcdhe) throws Exception {
        final byte[] ecServerPublicKeyRaw = Base64.getDecoder().decode(sharedSecretResponseEcdhe.getEcdhe());
        final PublicKey ecServerPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P384, ecServerPublicKeyRaw);
        final PrivateKey ecClientPrivateKey = sharedSecretClientContextEcdhe.getPrivateKey();
        final SecretKey sharedKey = KEY_GENERATOR.computeSharedKey(ecClientPrivateKey, ecServerPublicKey, true);
        return Kdf.derive(sharedKey, SHARED_SECRET_DERIVATION_INDEX, 32, null);
    }

}
