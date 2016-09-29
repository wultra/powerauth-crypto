package io.getlime.security.repository;

import io.getlime.security.repository.model.entity.IntegrationEntity;
import org.springframework.data.repository.CrudRepository;

/**
 * Database repository for the integration entities.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public interface IntegrationRepository extends CrudRepository<IntegrationEntity, String> {

    IntegrationEntity findFirstByClientToken(String clientToken);

}
