/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.lib.config;

public class PowerAuthConstants {

    /**
     * How many iterations should be used for PBKDF2 key derivation.
     */
    public static final int PBKDF_ITERATIONS = 10000;

    /**
     * When a duplicate activation ID is encountered during the activation, how
     * many times generate a new one.
     */
    public static final int ACTIVATION_GENERATE_ACTIVATION_ID_ITERATIONS = 10;

    /**
     * When a duplicate activation short ID is encountered during the
     * activation, how many times generate a new one.
     */
    public static final int ACTIVATION_GENERATE_ACTIVATION_SHORT_ID_ITERATIONS = 10;

    /**
     * How many milliseconds should be CREATED or OTP_USED record usable for
     * completing the activation.
     */
    public static final int ACTIVATION_VALIDITY_BEFORE_ACTIVE = 2 * 60 * 1000;

    /**
     * Length of device public key fingerprint.
     */
    public static final int FINGERPRINT_LENGTH = 8;

    /**
     * Signature length (number of decimal numbers representing signature)
     */
    public static final int SIGNATURE_LENGTH = 8;

    /**
     * How many failed signatures cause activation record blocking
     */
    public static final long SIGNATURE_MAX_FAILED_ATTEMPTS = 5L;

    /**
     * When validating the signature, how many iterations ahead too look
     */
    public static final long SIGNATURE_VALIDATION_LOOKAHEAD = 20L;

}
