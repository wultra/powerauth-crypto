package io.getlime.security.powerauth.app.rest.api.spring.provider;

import io.getlime.security.powerauth.rest.api.base.provider.PowerAuthUserProvider;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Component
public class DefaultUserProvider implements PowerAuthUserProvider {

    @Override
    public String lookupUserIdForAttributes(Map<String, String> identityAttributes) {
        return identityAttributes.get("username");
    }

    @Override
    public void processCustomActivationAttributes(Map<String, Object> customAttributes) {}

    @Override
    public boolean shouldAutoCommitActivation(Map<String, String> identityAttributes, Map<String, Object> customAttributes) {
        return true;
    }
}
