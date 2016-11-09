package io.getlime.push.repository;

import io.getlime.push.repository.model.AppCredentials;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository interface used to access app credentials database.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Repository
public interface AppCredentialsRepository extends CrudRepository<AppCredentials, Long> {

    /**
     * Find app push service credentials for given app ID.
     * @param appId App ID.
     * @return Push service app credentials.
     */
    AppCredentials findFirstByAppId(Long appId);

}
