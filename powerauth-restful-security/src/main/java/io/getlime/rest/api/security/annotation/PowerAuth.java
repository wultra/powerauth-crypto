package io.getlime.rest.api.security.annotation;

import io.getlime.security.powerauth.lib.enums.PowerAuthSignatureTypes;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface PowerAuth {

    public static final String AUTHENTICATION_OBJECT = "X-PowerAuth-Authentication-Object";

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
