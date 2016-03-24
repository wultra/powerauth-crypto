package io.getlime.security.repository.model.entity;

import java.io.Serializable;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;

/**
 * Entity class representing an application.
 * 
 * @author Petr Dvorak
 *
 */
@Entity(name = "pa_application")
public class ApplicationEntity implements Serializable {

	private static final long serialVersionUID = 1295434927785255417L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	@Column(name = "id")
	private Long id;
	
	@Column(name = "name")
	private String name;
	
	@OneToMany(mappedBy = "application")
	private List<ApplicationVersionEntity> versions;
	
	/**
	 * Default constructor
	 */
	public ApplicationEntity() { }
	
	/**
	 * Constructor for a new application
	 * @param id Application ID
	 * @param name Application name
	 * @param versions Collection of versions
	 */
	public ApplicationEntity(Long id, String name, List<ApplicationVersionEntity> versions) {
		super();
		this.id = id;
		this.name = name;
		this.versions = versions;
	}

	/**
	 * Get application ID
	 * @return Application ID
	 */
	public Long getId() {
		return id;
	}
	
	/**
	 * Set application ID
	 * @param id Application ID
	 */
	public void setId(Long id) {
		this.id = id;
	}
	
	/**
	 * Get application name
	 * @return Application name
	 */
	public String getName() {
		return name;
	}
	
	/**
	 * Set application name
	 * @param name Application name
	 */
	public void setName(String name) {
		this.name = name;
	}

}
