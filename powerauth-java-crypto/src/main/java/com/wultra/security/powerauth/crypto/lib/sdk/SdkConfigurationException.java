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

/**
 * Exception that may be thrown on SDK configuration serialization or deserialization error.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
public class SdkConfigurationException extends Exception {

    /**
     * Constructs a new exception with {@code null} as its detail message and cause.
     */
    public SdkConfigurationException() {
    }

    /**
     * Constructs a new exception with the specified detail message and {@code null} cause.
     * @param message the detail message.
     */
    public SdkConfigurationException(final String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     * @param message the detail message.
     * @param cause the cause.
     */
    public SdkConfigurationException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new exception with the specified cause.
     * @param cause the cause.
     */
    public SdkConfigurationException(final Throwable cause) {
        super(cause);
    }
}
