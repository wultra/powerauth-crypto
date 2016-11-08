package io.getlime.push.repository;

import io.getlime.push.repository.model.DeviceRegistration;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Repository interface used to access device registration database.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Repository
public interface DeviceRegistrationRepository extends CrudRepository<DeviceRegistration, Long> {

    DeviceRegistration findFirstByAppIdAndPushToken(Long appId, String pushToken);
    List<DeviceRegistration> findByActivationId(String activationId);
    List<DeviceRegistration> findByUserIdAndAppId(String userId, Long appId);
    List<DeviceRegistration> findByUserIdAndAppIdAndActivationId(String userId, Long appId, String activationId);

}
