package com.wultra.security.powerauth.crypto.lib.v4.model.request;

import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretRequest;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Default Shared Secret Request supporting multiple encapsulation keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DefaultSharedSecretRequest implements SharedSecretRequest {

    /**
     * Used algorithm.
     */
    private String algorithm;

    /**
     * Encapsulation keys encoded as Base64.
     */
    private List<String> encapsulationKeys;

}
