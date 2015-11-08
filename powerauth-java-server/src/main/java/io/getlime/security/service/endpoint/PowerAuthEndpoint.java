package io.getlime.security.service.endpoint;

import io.getlime.security.repository.PowerAuthRepository;
import io.getlime.security.powerauth.InitActivationRequest;
import io.getlime.security.powerauth.InitActivationResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;

@Endpoint
public class PowerAuthEndpoint {

    private static final String NAMESPACE_URI = "http://getlime.io/security/powerauth/";
    
    private PowerAuthRepository powerAuthRepository;

    @Autowired
    public PowerAuthEndpoint(PowerAuthRepository powerAuthRepository) {
        this.powerAuthRepository = powerAuthRepository;
    }

    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "initActivationRequest")
    @ResponsePayload
    public InitActivationResponse initActivation(@RequestPayload InitActivationRequest request) {
        InitActivationResponse response = new InitActivationResponse();
        response.setActivationIdShort("10");
        response.setActivationIdShort("20");
        response.setActivationIdShort("30");
        return response;
    }

}
