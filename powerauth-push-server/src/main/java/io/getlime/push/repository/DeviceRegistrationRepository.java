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

    /**
     * Find first device for given app ID and push token.
     * @param appId App ID.
     * @param pushToken Push token.
     * @return Device registration with provided values.
     */
    DeviceRegistration findFirstByAppIdAndPushToken(Long appId, String pushToken);

    /**
     * Find all device registrations by given activation ID. In normal case, the list will contain only one value.
     * @param activationId Activation ID.
     * @return List of device registrations.
     */
    List<DeviceRegistration> findByActivationId(String activationId);

    /**
     * Find all device registration by given user ID and app ID. This list represents all devices that a single user
     * has registered.
     * @param userId User ID.
     * @param appId App ID.
     * @return List of device registrations.
     */
    List<DeviceRegistration> findByUserIdAndAppId(String userId, Long appId);

    /**
     * Find all device registration by given user ID, app ID and activation ID. This list should contain one record
     * only under normal circumstances.
     * @param userId User ID.
     * @param appId App ID.
     * @param activationId Activation ID.
     * @return List of device registrations.
     */
    List<DeviceRegistration> findByUserIdAndAppIdAndActivationId(String userId, Long appId, String activationId);

}
