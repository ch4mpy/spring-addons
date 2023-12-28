package com.c4_soft.springaddons.security.oauth2.test;

import java.util.Optional;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockBearerTokenAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;

import reactor.core.publisher.Mono;

@Order(Ordered.LOWEST_PRECEDENCE)
@AutoConfiguration
public class AuthenticationFactoriesTestConf {

    @Bean
    WithJwt.AuthenticationFactory jwtAuthFactory(
            Optional<Converter<Jwt, ? extends AbstractAuthenticationToken>> jwtAuthenticationConverter,
            Optional<Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>> reactiveJwtAuthenticationConverter) {
        return new WithJwt.AuthenticationFactory(jwtAuthenticationConverter, reactiveJwtAuthenticationConverter);
    }

    @Bean
    WithOpaqueToken.AuthenticationFactory opaquetokenAuthFactory(
            Optional<OpaqueTokenAuthenticationConverter> authenticationConverter,
            Optional<ReactiveOpaqueTokenAuthenticationConverter> reactiveAuthenticationConverter) {
        return new WithOpaqueToken.AuthenticationFactory(authenticationConverter, reactiveAuthenticationConverter);
    }

    @Bean
    WithMockJwtAuth.JwtAuthenticationTokenFactory mockJwtAuthFactory(
            Optional<Converter<Jwt, ? extends AbstractAuthenticationToken>> jwtAuthenticationConverter,
            Optional<Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>> reactiveJwtAuthenticationConverter) {
        return new WithMockJwtAuth.JwtAuthenticationTokenFactory(jwtAuthenticationConverter, reactiveJwtAuthenticationConverter);
    }

    @Bean
    WithMockBearerTokenAuthentication.AuthenticationFactory mockBearerTokenAuthFactory(
            Optional<OpaqueTokenAuthenticationConverter> authenticationConverter,
            Optional<ReactiveOpaqueTokenAuthenticationConverter> reactiveAuthenticationConverter) {
        return new WithMockBearerTokenAuthentication.AuthenticationFactory(authenticationConverter, reactiveAuthenticationConverter);
    }
}
