/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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

package io.getlime.security.powerauth.app.server.service.util.model;

import java.util.ArrayList;
import java.util.List;

public class ServiceError {

    /**
     * Unknown error occurred.
     */
    public static final String UNKNOWN_ERROR = "ERR0000";

    /**
     * No user ID was set.
     */
    public static final String NO_USER_ID = "ERR0001";

    /**
     * No application ID was set.
     */
    public static final String NO_APPLICATION_ID = "ERR0002";

    /**
     * No master server key pair configured in database.
     */
    public static final String NO_MASTER_SERVER_KEYPAIR = "ERR0003";

    /**
     * Master server key pair contains private key in incorrect format.
     */
    public static final String INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE = "ERR0004";

    /**
     * Too many failed attempts to generate activation ID.
     */
    public static final String UNABLE_TO_GENERATE_ACTIVATION_ID = "ERR0005";

    /**
     * Too many failed attempts to generate short activation ID.
     */
    public static final String UNABLE_TO_GENERATE_SHORT_ACTIVATION_ID = "ERR0006";

    /**
     * This activation is already expired.
     */
    public static final String ACTIVATION_EXPIRED = "ERR0007";

    /**
     * Only activations in OTP_USED state can be committed.
     */
    public static final String ACTIVATION_INCORRECT_STATE = "ERR0008";

    /**
     * Activation with given activation ID was not found.
     */
    public static final String ACTIVATION_NOT_FOUND = "ERR0009";

    /**
     * Key with invalid format was provided.
     */
    public static final String INVALID_KEY_FORMAT = "ERR0010";

    /**
     * Invalid input parameter format.
     */
    public static final String INVALID_INPUT_FORMAT = "ERR0011";

    /**
     * Invalid Signature Provided.
     */
    public static final String INVALID_SIGNATURE = "ERR0012";

    /**
     * Unable to compute signature.
     */
    public static final String UNABLE_TO_COMPUTE_SIGNATURE = "ERR0013";

    public static List<String> allCodes() {
        List<String> list = new ArrayList<>(14);
        list.add(UNKNOWN_ERROR);
        list.add(NO_USER_ID);
        list.add(NO_APPLICATION_ID);
        list.add(NO_MASTER_SERVER_KEYPAIR);
        list.add(INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
        list.add(UNABLE_TO_GENERATE_ACTIVATION_ID);
        list.add(UNABLE_TO_GENERATE_SHORT_ACTIVATION_ID);
        list.add(ACTIVATION_EXPIRED);
        list.add(ACTIVATION_INCORRECT_STATE);
        list.add(ACTIVATION_NOT_FOUND);
        list.add(INVALID_KEY_FORMAT);
        list.add(INVALID_INPUT_FORMAT);
        list.add(INVALID_SIGNATURE);
        list.add(UNABLE_TO_COMPUTE_SIGNATURE);
        return list;
    }

}
