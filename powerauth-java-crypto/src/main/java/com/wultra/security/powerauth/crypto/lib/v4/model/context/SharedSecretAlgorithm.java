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

/**
 * Enumeration of supported shared secret algorithms.
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
    EC_P384_ML_L3

}
