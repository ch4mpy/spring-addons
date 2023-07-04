package com.c4_soft.springaddons.security.oauth2.test.mockmvc;

import java.util.Optional;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;

@TestConfiguration
public class AuthenticationFactoriesTestConf {

	@Bean
	WithJwt.AuthenticationFactory jwtAuthFactory(Optional<Converter<Jwt, ? extends AbstractAuthenticationToken>> jwtAuthenticationConverter) {
		return new WithJwt.AuthenticationFactory(jwtAuthenticationConverter, Optional.empty());
	}

	@Bean
	WithOpaqueToken.AuthenticationFactory opaquetokenAuthFactory(Optional<OpaqueTokenAuthenticationConverter> authenticationConverter) {
		return new WithOpaqueToken.AuthenticationFactory(authenticationConverter, Optional.empty());
	}
}
