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
import java.util.Date;
import java.util.Objects;

/**
 * Entity class representing Master Key Pair in the database.
 *
 * @author Petr Dvorak
 */
@Entity(name = "pa_master_keypair")
public class MasterKeyPairEntity implements Serializable {

    private static final long serialVersionUID = 1507932260603647825L;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id")
    private Long id;

    @Column(name = "name")
    private String name;

    @Column(name = "master_key_private_base64", nullable = false)
    private String masterKeyPrivateBase64;

    @Column(name = "master_key_public_base64", nullable = false)
    private String masterKeyPublicBase64;

    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated;

    @ManyToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false, updatable = false)
    private ApplicationEntity application;

    /**
     * Default constructor
     */
    public MasterKeyPairEntity() {
    }

    /**
     * Constructor for new master key pair entity.
     *
     * @param id                     Master Key Pair ID
     * @param name                   Name
     * @param masterKeyPrivateBase64 Private part encoded as Base64
     * @param masterKeyPublicBase64  Public part encoded as Base64
     * @param timestampCreated       Created timestamp.
     */
    public MasterKeyPairEntity(Long id, String name, String masterKeyPrivateBase64, String masterKeyPublicBase64, Date timestampCreated) {
        this.id = id;
        this.name = name;
        this.masterKeyPrivateBase64 = masterKeyPrivateBase64;
        this.masterKeyPublicBase64 = masterKeyPublicBase64;
        this.timestampCreated = timestampCreated;
    }

    /**
     * Get master key pair ID
     *
     * @return Master key pair ID
     */
    public Long getId() {
        return id;
    }

    /**
     * Set master key pair ID
     *
     * @param id Master key pair ID
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Get master key pair name
     *
     * @return Master key pair name
     */
    public String getName() {
        return name;
    }

    /**
     * Set master key pair name
     *
     * @param name Master key pair name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get master key pair private part encoded as Base64.
     *
     * @return Master key pair private part encoded as Base64.
     */
    public String getMasterKeyPrivateBase64() {
        return masterKeyPrivateBase64;
    }

    /**
     * Set master key pair private part encoded as Base64.
     *
     * @param masterKeyPrivateBase64 Master key pair private part encoded as Base64.
     */
    public void setMasterKeyPrivateBase64(String masterKeyPrivateBase64) {
        this.masterKeyPrivateBase64 = masterKeyPrivateBase64;
    }

    /**
     * Get master key pair public part encoded as Base64.
     *
     * @return Master key pair public part encoded as Base64.
     */
    public String getMasterKeyPublicBase64() {
        return masterKeyPublicBase64;
    }

    /**
     * Get master key pair public part encoded as Base64.
     *
     * @param masterKeyPublicBase64 Master key pair public part encoded as Base64.
     */
    public void setMasterKeyPublicBase64(String masterKeyPublicBase64) {
        this.masterKeyPublicBase64 = masterKeyPublicBase64;
    }

    /**
     * Get master key pair created timestamp.
     *
     * @return Master key pair created timestamp
     */
    public Date getTimestampCreated() {
        return timestampCreated;
    }

    /**
     * Set master key pair created timestamp.
     *
     * @param timestampCreated Master key pair created timestamp
     */
    public void setTimestampCreated(Date timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

    /**
     * Get master key pair associated application.
     *
     * @return Master key pair associated application
     */
    public ApplicationEntity getApplication() {
        return application;
    }

    /**
     * Set master key pair associated application.
     *
     * @param application Master key pair associated application
     */
    public void setApplication(ApplicationEntity application) {
        this.application = application;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 37 * hash + Objects.hashCode(this.id);
        hash = 37 * hash + Objects.hashCode(this.name);
        hash = 37 * hash + Objects.hashCode(this.masterKeyPrivateBase64);
        hash = 37 * hash + Objects.hashCode(this.masterKeyPublicBase64);
        hash = 37 * hash + Objects.hashCode(this.timestampCreated);
        hash = 37 * hash + Objects.hashCode(this.application);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final MasterKeyPairEntity other = (MasterKeyPairEntity) obj;
        if (!Objects.equals(this.name, other.name)) {
            return false;
        }
        if (!Objects.equals(this.id, other.id)) {
            return false;
        }
        if (!Objects.equals(this.masterKeyPrivateBase64, other.masterKeyPrivateBase64)) {
            return false;
        }
        if (!Objects.equals(this.masterKeyPublicBase64, other.masterKeyPublicBase64)) {
            return false;
        }
        if (!Objects.equals(this.timestampCreated, other.timestampCreated)) {
            return false;
        }
        if (!Objects.equals(this.application, other.application)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "MasterKeyPairEntity{"
                + "id=" + id
                + ", name=" + name
                + ", masterKeyPrivate=" + masterKeyPrivateBase64
                + ", masterKeyPublic=" + masterKeyPublicBase64
                + ", timestampCreated=" + timestampCreated
                + ", application=" + application.getId()
                + '}';
    }

}
