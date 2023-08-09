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

package io.getlime.security.powerauth.crypto.lib.encryptor.exception;

/**
 * Exception used for handling incorrect general encryption / decryption states.
 */
public class EncryptorException extends Exception {
    /**
     * Default constructor.
     */
    public EncryptorException() {
    }

    /**
     * Constructor with message.
     * @param message Message.
     */
    public EncryptorException(String message) {
        super(message);
    }

    /**
     * Construction with message and cause.
     * @param message Message.
     * @param cause Cause.
     */
    public EncryptorException(String message, Throwable cause) {
        super(message, cause);
    }
}
