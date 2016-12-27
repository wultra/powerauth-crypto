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

package io.getlime.security.powerauth.app.server.repository.model.entity;

import javax.persistence.*;
import java.io.Serializable;

/**
 * Entity class representing an application version. Each activation is associated with a single application,
 * that may have multiple versions.
 *
 * @author Petr Dvorak
 */
@Entity(name = "pa_application_version")
public class ApplicationVersionEntity implements Serializable {

    private static final long serialVersionUID = -5107229264389219556L;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false, updatable = false)
    private ApplicationEntity application;

    @Column(name = "name")
    private String name;

    @Column(name = "application_key")
    private String applicationKey;

    @Column(name = "application_secret")
    private String applicationSecret;

    @Column(name = "supported")
    private Boolean supported;

    /**
     * Get associated application
     *
     * @return Associated application
     */
    public ApplicationEntity getApplication() {
        return application;
    }

    /**
     * Set associated application
     *
     * @param application Associated application
     */
    public void setApplication(ApplicationEntity application) {
        this.application = application;
    }

    /**
     * Get application key
     *
     * @return Application key
     */
    public String getApplicationKey() {
        return applicationKey;
    }

    /**
     * Set application key
     *
     * @param applicationKey Application key
     */
    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    /**
     * Get application secret
     *
     * @return Application secret
     */
    public String getApplicationSecret() {
        return applicationSecret;
    }

    /**
     * Set application secret
     *
     * @param applicationSecret Application secret
     */
    public void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    /**
     * Get version ID
     *
     * @return version ID
     */
    public Long getId() {
        return id;
    }

    /**
     * Set version ID
     *
     * @param id Version ID
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Get version name
     *
     * @return Version name
     */
    public String getName() {
        return name;
    }

    /**
     * Set version name
     *
     * @param name Version name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get flag indicating if this version is still supported.
     *
     * @return Flag indicating if this version is still supported (can be used for signatures)
     */
    public Boolean getSupported() {
        return supported;
    }

    /**
     * Set flag indicating if this version is still supported.
     *
     * @param supported Flag indicating if this version is still supported (can be used for signatures)
     */
    public void setSupported(Boolean supported) {
        this.supported = supported;
    }

}
