package io.getlime.security.repository.model.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

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
	
	public ApplicationEntity getApplication() {
		return application;
	}
	
	public void setApplication(ApplicationEntity application) {
		this.application = application;
	}
	
	public String getApplicationKey() {
		return applicationKey;
	}
	
	public void setApplicationKey(String applicationKey) {
		this.applicationKey = applicationKey;
	}
	
	public String getApplicationSecret() {
		return applicationSecret;
	}
	
	public void setApplicationSecret(String applicationSecret) {
		this.applicationSecret = applicationSecret;
	}
	
	public Long getId() {
		return id;
	}
	
	public void setId(Long id) {
		this.id = id;
	}
	
	public String getName() {
		return name;
	}
	
	public void setName(String name) {
		this.name = name;
	}
	
	public Boolean getSupported() {
		return supported;
	}
	
	public void setSupported(Boolean supported) {
		this.supported = supported;
	}
	
}
