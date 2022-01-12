package com.c4_soft.springaddons.samples.webmvc.jpa;

import java.util.Set;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
public class Proxy {
	@Id
	@GeneratedValue
	private Long id;

	@ManyToOne
	@JoinColumn(nullable = false)
	private User proxiedUser;

	@ManyToMany()
	private Set<Grant> grants;
}
