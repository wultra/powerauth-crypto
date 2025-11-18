package com.wultra.security.powerauth.crypto.lib.v4.model.response;

import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Default Shared Secret Response supporting multiple encapsulated keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DefaultSharedSecretResponse implements SharedSecretResponse {

    /**
     * Salt used during shared secret key derivation.
     */
    private byte[] salt;

    /**
     * Encapsulated keys encoded as Base64.
     */
    private List<String> encapsulatedKeys;

}
