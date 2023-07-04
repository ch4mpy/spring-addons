package com.c4_soft.springaddons.security.oauth2.test.webflux;

import java.util.Optional;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;

import reactor.core.publisher.Mono;

@TestConfiguration
public class AuthenticationFactoriesTestConf {


	@Bean
	WithJwt.AuthenticationFactory jwtAuthFactory(Optional<Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>> authenticationConverter) {
		return new WithJwt.AuthenticationFactory(Optional.empty(), authenticationConverter);
	}

	@Bean
	WithOpaqueToken.AuthenticationFactory opaquetokenAuthFactory(Optional<ReactiveOpaqueTokenAuthenticationConverter> authenticationConverter) {
		return new WithOpaqueToken.AuthenticationFactory(Optional.empty(), authenticationConverter);
	}

}