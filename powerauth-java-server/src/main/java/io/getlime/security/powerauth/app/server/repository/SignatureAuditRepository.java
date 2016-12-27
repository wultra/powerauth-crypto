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

import io.getlime.security.powerauth.app.server.repository.model.entity.SignatureEntity;
import org.springframework.data.repository.CrudRepository;

import java.util.Date;
import java.util.List;

/**
 * Database repository for accessing signature audit log data.
 *
 * @author Petr Dvorak
 */
public interface SignatureAuditRepository extends CrudRepository<SignatureEntity, Long> {

    /**
     * Return signature audit records for given user and date range.
     *
     * @param userId       User ID.
     * @param startingDate Starting date (date "from").
     * @param endingDate   Ending date (date "to").
     * @return List of {@link SignatureEntity} instances.
     */
    List<SignatureEntity> findByActivation_UserIdAndTimestampCreatedBetweenOrderByTimestampCreatedDesc(String userId, Date startingDate, Date endingDate);

    /**
     * Return signature audit records for given user, application and date range.
     *
     * @param applicationId Application ID.
     * @param userId        User ID.
     * @param startingDate  Starting date (date "from").
     * @param endingDate    Ending date (date "to").
     * @return List of {@link SignatureEntity} instances.
     */
    List<SignatureEntity> findByActivation_ApplicationIdAndActivation_UserIdAndTimestampCreatedBetweenOrderByTimestampCreatedDesc(Long applicationId, String userId, Date startingDate, Date endingDate);

}
