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
package io.getlime.security.repository.model;

public enum ActivationStatus {

    CREATED((byte) 1),
    OTP_USED((byte) 2),
    ACTIVE((byte) 3),
    BLOCKED((byte) 4),
    REMOVED((byte) 5);

    final byte value;

    ActivationStatus(final byte value) {
        this.value = value;
    }

    public byte getByte() {
        return value;
    }
}
