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
package io.getlime.security.powerauth.app.server.repository;

import io.getlime.security.powerauth.app.server.repository.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.repository.model.entity.ActivationRecordEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * Database repository for activation entities.
 *
 * @author Petr Dvorak
 */
@Component
public interface ActivationRepository extends CrudRepository<ActivationRecordEntity, String> {

    /**
     * Find a first activation with given activation ID
     *
     * @param activationId Activation ID
     * @return Activation with given ID or null if not found
     */
    ActivationRecordEntity findFirstByActivationId(String activationId);

    /**
     * Find all activations for given user ID
     *
     * @param userId User ID
     * @return List of activations for given user
     */
    List<ActivationRecordEntity> findByUserId(String userId);

    /**
     * Find all activations for given user ID and application ID
     *
     * @param applicationId Application ID
     * @param userId        User ID
     * @return List of activations for given user and application
     */
    List<ActivationRecordEntity> findByApplicationIdAndUserId(Long applicationId, String userId);

    /**
     * Find the first activation associated with given application by the activation ID short.
     * Filter the results by activation state and make sure to apply activation time window.
     *
     * @param applicationId     Application ID
     * @param activationIdShort Short activation ID
     * @param states            Allowed activation states
     * @param currentTimestamp  Current timestamp
     * @return Activation matching the search criteria or null if not found
     */
    ActivationRecordEntity findFirstByApplicationIdAndActivationIdShortAndActivationStatusInAndTimestampActivationExpireAfter(Long applicationId, String activationIdShort, Collection<ActivationStatus> states, Date currentTimestamp);

}
