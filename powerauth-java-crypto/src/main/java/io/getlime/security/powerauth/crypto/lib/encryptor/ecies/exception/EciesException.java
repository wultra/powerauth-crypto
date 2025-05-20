/*
 * PowerAuth Crypto Library
 * Copyright 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception;

import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;

/**
 * Exception used for handling incorrect ECIES encryption / decryption states.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class EciesException extends EncryptorException {

    /**
     * Default constructor.
     */
    public EciesException() {
    }

    /**
     * Constructor with message.
     * @param message Message.
     */
    public EciesException(String message) {
        super(message);
    }

    /**
     * Construction with message and cause.
     * @param message Message.
     * @param cause Cause.
     */
    public EciesException(String message, Throwable cause) {
        super(message, cause);
    }
}
