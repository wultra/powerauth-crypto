package io.getlime.security.repository;

import org.springframework.data.repository.CrudRepository;

import io.getlime.security.repository.model.entity.ApplicationEntity;

/**
 * Database repository class for access to applications
 * 
 * @author Petr Dvorak
 *
 */
public interface ApplicationRepository extends CrudRepository<ApplicationEntity, Long> {

	
}
