package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.util.Map;

import org.springframework.security.authentication.AbstractAuthenticationToken;

// FIXME: replace with the outcome of when https://github.com/spring-projects/spring-security/issues/11661
public interface OAuth2AuthenticationFactory<T extends AbstractAuthenticationToken> {
	T build(String bearerString, Map<String, Object> claims);
}
