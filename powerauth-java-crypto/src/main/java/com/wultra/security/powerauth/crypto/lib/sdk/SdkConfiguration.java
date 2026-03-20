/*
 * PowerAuth Crypto Library
 * Copyright 2026 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.lib.sdk;

import lombok.Builder;

/**
 * Parameters for configuring PowerAuth Mobile SDK.
 *
 * @param appKey Application key.
 * @param appSecret Application secret.
 * @param masterPublicKeyP256 Master server public key for ECDSA P-256, or {@code null} if not used.
 * @param masterPublicKeyP384 Master server public key for ECDSA P-384, or {@code null} if not used.
 * @param masterPublicKeyMlDsa65 Master server public key for ML-DSA-65, or {@code null} if not used.
 * @param masterPublicKeyMlDsa87 Master server public key for ML-DSA-87, or {@code null} if not used
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Builder
public record SdkConfiguration(
        String appKey,
        String appSecret,
        String masterPublicKeyP256,
        String masterPublicKeyP384,
        String masterPublicKeyMlDsa65,
        String masterPublicKeyMlDsa87) {
}
