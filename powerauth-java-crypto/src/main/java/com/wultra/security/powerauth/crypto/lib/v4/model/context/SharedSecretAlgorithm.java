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

package com.wultra.security.powerauth.crypto.lib.v4.model.context;

import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

/**
 * Enumeration of supported shared secret algorithm suites.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public enum SharedSecretAlgorithm {

    /**
     * EC with P-256 curve.
     */
    EC_P256,

    /**
     * EC with P-384 curve.
     */
    EC_P384,

    /**
     * EC with P-384 curve and ML with level 3 (ML-KEM-768 / ML-DSA-65).
     */
    EC_P384_ML_L3,

    /**
     * EC with P-384 curve and ML with level 5 (ML-KEM-1024 / ML-DSA-87).
     */
    EC_P384_ML_L5,

    /**
     * ML with level 3 (ML-KEM-768 / ML-DSA-65), testing only.
     */
    ML_L3,

    /**
     * ML with level 3 (ML-KEM-1024 / ML-DSA-87), testing only.
     */
    ML_L5;

    /**
     * Get EC curve for this algorithm suite.
     * @return EC curve.
     */
    public EcCurve getEcCurve() {
        return switch (this) {
            case EC_P256 -> EcCurve.P256;
            case EC_P384, EC_P384_ML_L3, EC_P384_ML_L5 -> EcCurve.P384;
            default -> null;
        };
    }

    /**
     * Get ML-KEM parameter specification for this algorithm suite.
     * @return ML-KEM parameter specification.
     */
    public MLKEMParameterSpec getMlKemParameterSpec() {
        return switch (this) {
            case EC_P384_ML_L3, ML_L3 -> MLKEMParameterSpec.ml_kem_768;
            case EC_P384_ML_L5, ML_L5 -> MLKEMParameterSpec.ml_kem_1024;
            default -> null;
        };
    }

    /**
     * Get ML-DSA parameter specification for this algorithm suite.
     * @return ML-DSA parameter specification.
     */
    public MLDSAParameterSpec getMlDsaParameterSpec() {
        return switch (this) {
            case EC_P384_ML_L3, ML_L3 -> MLDSAParameterSpec.ml_dsa_65;
            case EC_P384_ML_L5, ML_L5 -> MLDSAParameterSpec.ml_dsa_87;
            default -> null;
        };
    }

}
