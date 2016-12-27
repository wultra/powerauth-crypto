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

package io.getlime.security.powerauth.rest.api.spring.annotation;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface PowerAuth {

    String AUTHENTICATION_OBJECT = "X-PowerAuth-Authentication-Object";

    /**
     * Identifier of the resource URI, usually the "effective" part of the URL, for example
     * "/banking/payment/commit".
     *
     * @return Resource identifier.
     */
    String resourceId();

    /**
     * Types of supported signatures. By default, any at least 2FA signature type must be specified.
     *
     * @return Supported signature types.
     */
    PowerAuthSignatureTypes[] signatureType() default {
            PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
    };

}
