package io.getlime.security.repository;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import io.getlime.security.repository.model.entity.ApplicationVersionEntity;

/**
 * Database repository for access to application versions.
 * 
 * @author Petr Dvorak
 *
 */
public interface ApplicationVersionRepository extends CrudRepository<ApplicationVersionEntity, Long> {
	
	/**
	 * Get all versions for given application.
	 * @param applicationId Application ID
	 * @return List of versions
	 */
	public List<ApplicationVersionEntity> findByApplicationId(Long applicationId);
	
	/**
	 * Find version by application key.
	 * @param applicationKey Application key.
	 * @return Version with given application key.
	 */
	public ApplicationVersionEntity findByApplicationKey(String applicationKey);

}
