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
package com.wultra.security.powerauth.crypto.lib.model;

import lombok.Data;

/**
 * Information about activation status as parsed from the blob provided by
 * calling /pa/activation/status end-point.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Data
public class ActivationStatusBlobInfo {

    /**
     * Activation status magic value for protocol version 3.x.
     */
    public static final int ACTIVATION_STATUS_MAGIC_VALUE_V3 = 0xDEC0DED1;

    /**
     * Activation status magic value for protocol version 4.x.
     */
    public static final int ACTIVATION_STATUS_MAGIC_VALUE_V4 = 0xDEC0DED4;

    private boolean valid;
    private byte activationStatus;
    private byte currentVersion;
    private byte upgradeVersion;
    private byte statusFlags;
    private byte failedAttempts;
    private byte maxFailedAttempts;
    private byte ctrLookAhead;
    private byte ctrByte;
    private byte[] ctrDataHash;

}
