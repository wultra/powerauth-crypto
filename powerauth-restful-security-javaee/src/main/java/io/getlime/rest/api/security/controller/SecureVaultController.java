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

package io.getlime.rest.api.security.controller;

import com.google.common.io.BaseEncoding;
import io.getlime.powerauth.soap.PowerAuthPortServiceStub;
import io.getlime.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.rest.api.model.response.VaultUnlockResponse;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;
import io.getlime.rest.api.security.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpHeader;
import io.getlime.security.soap.axis.client.PowerAuthServiceClient;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.util.Map;

/**
 * Controller implementing secure vault related end-points from the
 * PowerAuth Standard API.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Path("pa/vault")
@Produces(MediaType.APPLICATION_JSON)
public class SecureVaultController {

    @Inject
    private PowerAuthServiceClient powerAuthClient;

    /**
     * Request the vault unlock key.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @return PowerAuth RESTful response with {@link VaultUnlockResponse} payload.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     * @throws UnsupportedEncodingException In case UTF-8 is not supported.
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("unlock")
    public PowerAuthApiResponse<VaultUnlockResponse> unlockVault(
            @HeaderParam(PowerAuthHttpHeader.HEADER_NAME) String signatureHeader)
            throws PowerAuthAuthenticationException, PowerAuthSecureVaultException {
        try {
            Map<String, String> map = PowerAuthHttpHeader.parsePowerAuthSignatureHTTPHeader(signatureHeader);
            String activationId = map.get(PowerAuthHttpHeader.ACTIVATION_ID);
            String applicationId = map.get(PowerAuthHttpHeader.APPLICATION_ID);
            String signature = map.get(PowerAuthHttpHeader.SIGNATURE);
            String signatureType = map.get(PowerAuthHttpHeader.SIGNATURE_TYPE);
            String nonce = map.get(PowerAuthHttpHeader.NONCE);

            String data = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/vault/unlock", BaseEncoding.base64().decode(nonce), null);

            PowerAuthPortServiceStub.VaultUnlockResponse soapResponse = powerAuthClient.unlockVault(activationId, applicationId, data, signature, signatureType);

            if (!soapResponse.getSignatureValid()) {
                throw new PowerAuthAuthenticationException();
            }

            VaultUnlockResponse response = new VaultUnlockResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setEncryptedVaultEncryptionKey(soapResponse.getEncryptedVaultEncryptionKey());

            return new PowerAuthApiResponse<>("OK", response);
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PowerAuthSecureVaultException();
        }
    }

}
