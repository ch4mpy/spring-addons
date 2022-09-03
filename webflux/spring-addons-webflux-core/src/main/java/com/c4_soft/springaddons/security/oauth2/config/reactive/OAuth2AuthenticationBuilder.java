package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.util.Map;

import org.springframework.security.core.Authentication;

import reactor.core.publisher.Mono;

// FIXME: replace with the outcome of when https://github.com/spring-projects/spring-security/issues/11661
public interface OAuth2AuthenticationBuilder<T extends Authentication> {
	Mono<T> build(String bearerString, Map<String, Object> claims);
}
