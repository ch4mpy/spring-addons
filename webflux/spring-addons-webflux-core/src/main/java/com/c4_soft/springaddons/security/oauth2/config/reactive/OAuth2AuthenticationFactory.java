package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.util.Map;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import reactor.core.publisher.Mono;

// FIXME: replace with the outcome of when https://github.com/spring-projects/spring-security/issues/11661
public interface OAuth2AuthenticationFactory {
	Mono<AbstractAuthenticationToken> build(String bearerString, Map<String, Object> claims);
}
