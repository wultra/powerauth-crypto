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
package io.getlime.security.powerauth.crypto.lib.model.exception;

/**
 * Exception used for handling case when cryptography provider is incorrectly initialized.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class CryptoProviderException extends Exception {

    /**
     * Exception without error message.
     */
    public CryptoProviderException() {
        super();
    }

    /**
     * Exception with error message.
     * @param message Error message.
     */
    public CryptoProviderException(String message) {
        super(message);
    }

    /**
     * Exception with error message and cause.
     * @param message Error message.
     * @param cause Exception cause.
     */
    public CryptoProviderException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Exception with cause.
     * @param cause Exception cause.
     */
    public CryptoProviderException(Throwable cause) {
        super(cause);
    }
}
