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
package io.getlime.security.powerauth.app.server.repository.model;

import io.getlime.security.powerauth.app.server.service.PowerAuthService;

/**
 * Enum representing possible activation states. Following values are supported:
 * <p>
 * - CREATED = 1
 * - OTP_USED = 2
 * - ACTIVE = 3
 * - BLOCKED = 4
 * - REMOVED = 5
 *
 * @author Petr Dvorak
 */
public enum ActivationStatus {

    /**
     * CREATED - status right after the activation record was created by calling
     * {@link PowerAuthService#initActivation(io.getlime.security.powerauth.InitActivationRequest)}.
     */
    CREATED((byte) 1),

    /**
     * OTP_USED - status right after PowerAuth 2.0 Server receives PowerAuth 2.0 Client public
     * key, via {@link PowerAuthService#prepareActivation(io.getlime.security.powerauth.PrepareActivationRequest)}
     * method.
     */
    OTP_USED((byte) 2),

    /**
     * ACTIVE - status after the activation record was committed by calling
     * {@link PowerAuthService#commitActivation(io.getlime.security.powerauth.CommitActivationRequest)},
     * or after activation was unblocked from the BLOCKED state by calling
     * {@link PowerAuthService#unblockActivation(io.getlime.security.powerauth.UnblockActivationRequest)}.
     */
    ACTIVE((byte) 3),

    /**
     * BLOCKED - status after the activation record was blocked by calling
     * {@link PowerAuthService#blockActivation(io.getlime.security.powerauth.BlockActivationRequest)} or
     * after too many authentication failed attempt occurred.
     */
    BLOCKED((byte) 4),

    /**
     * REMOVED - status after the activation record was removed by calling
     * {@link PowerAuthService#removeActivation(io.getlime.security.powerauth.RemoveActivationRequest)}.
     */
    REMOVED((byte) 5);

    final byte value;

    ActivationStatus(final byte value) {
        this.value = value;
    }

    /**
     * Get byte representation of the enum value.
     *
     * @return Byte representing enum value.
     */
    public byte getByte() {
        return value;
    }
}
