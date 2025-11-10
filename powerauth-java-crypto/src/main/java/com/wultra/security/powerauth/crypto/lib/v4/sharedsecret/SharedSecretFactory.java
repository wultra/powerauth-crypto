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

import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecret;
import com.wultra.security.powerauth.crypto.lib.v4.dh.DhKem;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlKem;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.DefaultSharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.DefaultSharedSecretRequest;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.DefaultSharedSecretResponse;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

import java.util.List;

/**
 * shared secret algorithm implementation factory.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public final class SharedSecretFactory {

    private static final SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> SHARED_SECRET_ECDHE =
            new DefaultSharedSecret(
                    SharedSecretAlgorithm.EC_P384,
                    List.of(new DhKem())
            );

    private static final SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> SHARED_SECRET_HYBRID_ML_L3 =
            new DefaultSharedSecret(
                    SharedSecretAlgorithm.EC_P384_ML_L3,
                    List.of(
                            new DhKem(),
                            new MlKem(MLKEMParameterSpec.ml_kem_768)
                    )
            );

    private static final SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> SHARED_SECRET_HYBRID_ML_L5 =
            new DefaultSharedSecret(
                    SharedSecretAlgorithm.EC_P384_ML_L5,
                    List.of(
                            new DhKem(),
                            new MlKem(MLKEMParameterSpec.ml_kem_1024)
                    )
            );

    private static final SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> SHARED_SECRET_ML_L3 =
            new DefaultSharedSecret(
                    SharedSecretAlgorithm.ML_L3,
                    List.of(new MlKem(MLKEMParameterSpec.ml_kem_768))
            );

    private static final SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> SHARED_SECRET_ML_L5 =
            new DefaultSharedSecret(
                    SharedSecretAlgorithm.ML_L5,
                    List.of(new MlKem(MLKEMParameterSpec.ml_kem_1024))
            );

    /**
     * Private constructor.
     */
    private SharedSecretFactory() {
    }

    /**
     * Get ECDHE (P-384) shared secret algorithm implementation.
     * @return ECDHE (P-384) shared secret algorithm implementation.
     */
    public static SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> getEcdhe() {
        return SHARED_SECRET_ECDHE;
    }

    /**
     * Get ECDHE (P-384) + ML-KEM (level 3) shared secret algorithm implementation.
     * @return ECDHE (P-384) + ML-KEM (level 3) shared secret algorithm implementation.
     */
    public static SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> getHybridMlL3() {
        return SHARED_SECRET_HYBRID_ML_L3;
    }

    /**
     * Get ECDHE (P-384) + ML-KEM (level 5) shared secret algorithm implementation.
     * @return ECDHE (P-384) + ML-KEM (level 5) shared secret algorithm implementation.
     */
    public static SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> getHybridMlL5() {
        return SHARED_SECRET_HYBRID_ML_L5;
    }

    /**
     * Get ML-KEM (level 3) shared secret algorithm implementation.
     * @return ML-KEM (level 3) shared secret algorithm implementation.
     */
    public static SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> getMlL3() {
        return SHARED_SECRET_ML_L3;
    }

    /**
     * Get ML-KEM (level 5) shared secret algorithm implementation.
     * @return ML-KEM (level 5) shared secret algorithm implementation.
     */
    public static SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> getMlL5() {
        return SHARED_SECRET_ML_L5;
    }

    /**
     * Get shared secret implementation for a shared secret algorithm.
     * @param algorithm Shared secret algorithm.
     * @return Shared secret algorithm implementation.
     */
    public static SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> forAlgorithm(SharedSecretAlgorithm algorithm) {
        return switch (algorithm) {
            case EC_P384 -> SHARED_SECRET_ECDHE;
            case EC_P384_ML_L3 -> SHARED_SECRET_HYBRID_ML_L3;
            case EC_P384_ML_L5 -> SHARED_SECRET_HYBRID_ML_L5;
            case ML_L3 -> SHARED_SECRET_ML_L3;
            case ML_L5 -> SHARED_SECRET_ML_L5;
            default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        };
    }

}