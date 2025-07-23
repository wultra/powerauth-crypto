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

package com.wultra.security.powerauth.crypto.lib.v4.model;

import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretClientContext;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.security.PrivateKey;

/**
 * Shared secret client context object for ECDHE on P-384.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SharedSecretClientContextEcdhe implements SharedSecretClientContext {

    /**
     * Client EC private key.
     */
    @ToString.Exclude
    private PrivateKey privateKey;

}
