package io.getlime.security.service.behavior;

import io.getlime.security.powerauth.*;
import io.getlime.security.repository.IntegrationRepository;
import io.getlime.security.repository.model.entity.IntegrationEntity;
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

    @Autowired
    public IntegrationBehavior(IntegrationRepository integrationRepository) {
        this.integrationRepository = integrationRepository;
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
