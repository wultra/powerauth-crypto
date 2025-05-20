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

package io.getlime.security.powerauth.crypto.lib.encryptor.model;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * The {@code EncryptorParameters} object contains shared parameters that affects what type of {@code ServerEncryptor}
 * or {@code ClientEncryptor} is constructed in {@code EncryptorFactory}. The parameters are typically extracted from
 * the HTTP request header on the server side implementation.
 *
 * @see io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory
 */
@Data
@AllArgsConstructor
public class EncryptorParameters {
    private String protocolVersion;
    private String applicationKey;
    private String activationIdentifier;
    private String temporaryKeyId;
}
