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

package io.getlime.security.powerauth.app.server.service.behavior;

import io.getlime.security.powerauth.*;
import io.getlime.security.powerauth.app.server.repository.IntegrationRepository;
import io.getlime.security.powerauth.app.server.repository.model.entity.IntegrationEntity;
import io.getlime.security.powerauth.app.server.service.configuration.PowerAuthServiceConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Class that manages the service logic related to integration management.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Component
public class IntegrationBehavior {

    private IntegrationRepository integrationRepository;
    private PowerAuthServiceConfiguration configuration;

    @Autowired
    public IntegrationBehavior(IntegrationRepository integrationRepository) {
        this.integrationRepository = integrationRepository;
    }

    @Autowired
    public void setConfiguration(PowerAuthServiceConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * Creates a new integration record for application with given name, and automatically generates credentials.
     * @param request CreateIntegraionRequest instance specifying name of new integration.
     * @return Newly created integration information.
     */
    public CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) {
        IntegrationEntity entity = new IntegrationEntity();
        entity.setName(request.getName());
        entity.setId(UUID.randomUUID().toString());
        entity.setClientToken(UUID.randomUUID().toString());
        entity.setClientSecret(UUID.randomUUID().toString());
        integrationRepository.save(entity);
        CreateIntegrationResponse response = new CreateIntegrationResponse();
        response.setId(entity.getId());
        response.setName(entity.getName());
        response.setClientToken(entity.getClientToken());
        response.setClientSecret(entity.getClientSecret());
        return response;
    }

    /**
     * Get the list of all current integrations.
     * @return List of all current integrations.
     */
    public GetIntegrationListResponse getIntegrationList(GetIntegrationListRequest request) {
        final Iterable<IntegrationEntity> integrations = integrationRepository.findAll();
        GetIntegrationListResponse response = new GetIntegrationListResponse();
        response.setRestrictedAccess(configuration.getRestrictAccess());
        for (IntegrationEntity i: integrations) {
            GetIntegrationListResponse.Items item = new GetIntegrationListResponse.Items();
            item.setId(i.getId());
            item.setName(i.getName());
            item.setClientToken(i.getClientToken());
            item.setClientSecret(i.getClientSecret());
            response.getItems().add(item);
        }
        return response;
    }

    /**
     * Remove integration with given ID.
     * @param request Request specifying the integration to be removed.
     * @return Information about removal status.
     */
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) {
        RemoveIntegrationResponse response = new RemoveIntegrationResponse();
        response.setId(request.getId());
        if (integrationRepository.findOne(request.getId()) != null) {
            response.setRemoved(true);
        } else {
            response.setRemoved(false);
        }
        integrationRepository.delete(request.getId());
        return response;
    }

}
