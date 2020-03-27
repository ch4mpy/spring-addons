package com.c4_soft.springaddons.samples.webmvc.common.domain;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;

public interface MessageService<T extends Authentication> {

	@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
	String getSecret();

	@PreAuthorize("authenticated")
	String greet(T who);

}
