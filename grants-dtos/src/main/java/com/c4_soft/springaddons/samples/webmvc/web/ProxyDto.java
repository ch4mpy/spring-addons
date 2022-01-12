package com.c4_soft.springaddons.samples.webmvc.web;

import java.util.Collection;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.xml.bind.annotation.XmlRootElement;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@XmlRootElement
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ProxyDto {

	@NotNull
	@NotEmpty
	private String proxiedUserSubject;

	@NotNull
	private Collection<Long> grantIds;

}
