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
import com.wultra.security.powerauth.crypto.lib.v4.model.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class SharedSecretEcdheTest {

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testEcdhe_Success() throws Exception {
        SharedSecretEcdhe sharedSecretEcdhe = new SharedSecretEcdhe();
        RequestCryptogram request = sharedSecretEcdhe.generateRequestCryptogram();
        assertNotNull(request);
        assertNotNull(request.getSharedSecretRequest());
        assertNotNull(request.getSharedSecretClientContext());

        KeyPair ecClientKeyPair = KEY_GENERATOR.generateKeyPair(EcCurve.P384);
        SharedSecretClientContextEcdhe clientContext = new SharedSecretClientContextEcdhe(ecClientKeyPair.getPrivate());

        byte[] ecClientPublicKeyRaw = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P384, ecClientKeyPair.getPublic());
        String ecClientPublicKeyBase64 = Base64.getEncoder().encodeToString(ecClientPublicKeyRaw);
        SharedSecretRequestEcdhe clientRequest = new SharedSecretRequestEcdhe(ecClientPublicKeyBase64);

        ResponseCryptogram serverResponse = sharedSecretEcdhe.generateResponseCryptogram(clientRequest);
        assertNotNull(serverResponse);
        assertNotNull(serverResponse.getSharedSecretResponse());
        assertNotNull(serverResponse.getSecretKey());

        SecretKey serverSharedSecret = sharedSecretEcdhe.computeSharedSecret(
                clientContext,
                (SharedSecretResponseEcdhe) serverResponse.getSharedSecretResponse()
        );
        assertNotNull(serverSharedSecret);

        assertEquals(
                serverSharedSecret,
                serverResponse.getSecretKey()
        );
    }

}