package io.getlime.security.repository;

import io.getlime.security.repository.model.entity.ApplicationEntity;
import org.springframework.data.repository.CrudRepository;

/**
 * Database repository class for access to applications
 *
 * @author Petr Dvorak
 */
public interface ApplicationRepository extends CrudRepository<ApplicationEntity, Long> {


}
