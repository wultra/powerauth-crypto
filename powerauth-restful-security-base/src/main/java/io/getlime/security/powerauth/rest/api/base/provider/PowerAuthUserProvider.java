package io.getlime.security.powerauth.rest.api.base.provider;

import java.util.Map;

/**
 * Interface that specifies a method for obtaining a user ID based on arbitrary attributes.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public interface PowerAuthUserProvider {

    /**
     * This method is responsible for looking user ID up based on a provided set of identity attributes.
     * @param identityAttributes Attributes that uniquely identify user with given ID.
     * @return User ID value.
     */
    String lookupUserIdForAttributes(Map<String, String> identityAttributes);

    /**
     * Variable that specifies if the activation should be automatically commited based on provided attributes.
     * Return true in case you would like to create an activation that is ready to be used for signing (ACTIVE),
     * and false for the cases when you need activation to remain in OTP_USED state.
     *
     * @param identityAttributes Identity related attributes.
     * @param customAttributes Custom attributes, not related to identity.
     * @return True in case activation should be commited, false otherwise.
     */
    boolean shouldAutoCommitActivation(Map<String, String> identityAttributes, Map<String, Object> customAttributes);

    /**
     * Process custom attributes, in any way that is suitable for the purpose of your application.
     * @param customAttributes Custom attributes (not related to identity) to be processed.
     */
    void processCustomActivationAttributes(Map<String, Object> customAttributes);

}
