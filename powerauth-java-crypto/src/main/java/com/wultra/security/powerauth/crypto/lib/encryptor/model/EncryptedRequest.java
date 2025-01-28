/*
 * PowerAuth Crypto Library
 * Copyright 2023 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.lib.encryptor.model;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * The {@code EncryptedRequest} object represents an encrypted request payload in PowerAuth End-To-End encryption scheme.
 */
@Data
@AllArgsConstructor
public class EncryptedRequest {
    private String temporaryKeyId;
    private String ephemeralPublicKey;
    private String encryptedData;
    private String mac;
    private String nonce;
    private Long timestamp;
}