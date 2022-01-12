package com.c4_soft.springaddons.samples.webmvc.web;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

import javax.validation.constraints.NotNull;
import javax.xml.bind.annotation.XmlRootElement;

import lombok.Data;
import lombok.NoArgsConstructor;

@XmlRootElement
@Data
@NoArgsConstructor
public class UserProxiesDto {

	@NotNull
	private Map<String, Collection<Long>> grantsByProxiedUserSubject;

	public UserProxiesDto(Collection<ProxyDto> proxies) {
		this.grantsByProxiedUserSubject = proxies.stream().collect(Collectors.toMap(ProxyDto::getProxiedUserSubject, ProxyDto::getGrantIds));
	}
}
