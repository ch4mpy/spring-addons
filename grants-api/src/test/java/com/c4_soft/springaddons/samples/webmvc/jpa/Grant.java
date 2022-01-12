package com.c4_soft.springaddons.samples.webmvc.jpa;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
public class Grant {
	@Id
	@GeneratedValue
	private Long id;

	private String label;
}
