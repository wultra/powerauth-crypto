package com.wultra.security.powerauth.crypto.lib.v4.model.context;

import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretClientContext;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.security.PrivateKey;
import java.util.List;

/**
 * Client context for default shared secret, holding decapsulation private keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DefaultSharedSecretClientContext implements SharedSecretClientContext {

    /**
     * List of private decapsulation keys corresponding to the KEM list.
     */
    @ToString.Exclude
    private List<PrivateKey> decapsulationKeys;
}
