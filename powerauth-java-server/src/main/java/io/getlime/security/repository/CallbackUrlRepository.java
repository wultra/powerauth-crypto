package io.getlime.security.repository;

import io.getlime.security.repository.model.entity.CallbackUrlEntity;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

/**
 * Database repository for the callback URL entities.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public interface CallbackUrlRepository extends CrudRepository<CallbackUrlEntity, String> {

    List<CallbackUrlEntity> findByApplicationIdOrderByName(Long applicationId);

}
