package io.getlime.security.powerauth.app.rest.api.javaee.controller.model;

import io.getlime.security.powerauth.rest.api.model.request.ActivationCreateRequest;

import java.util.Map;

/**
 * Request object for /pa/activation/direct/create end-point.
 *
 * Object representing an activation performed with given identity, custom (non-identity related) attributes, and
 * PowerAuth 2.0 activation object.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class ActivationCreateCustomRequest {

    private Map<String, String> identity;
    private Map<String, Object> customAttributes;
    private ActivationCreateRequest powerauth;

    public Map<String, String> getIdentity() {
        return identity;
    }

    public void setIdentity(Map<String, String> identity) {
        this.identity = identity;
    }

    public Map<String, Object> getCustomAttributes() {
        return customAttributes;
    }

    public void setCustomAttributes(Map<String, Object> customAttributes) {
        this.customAttributes = customAttributes;
    }

    public ActivationCreateRequest getPowerauth() {
        return powerauth;
    }

    public void setPowerauth(ActivationCreateRequest powerauth) {
        this.powerauth = powerauth;
    }
}
