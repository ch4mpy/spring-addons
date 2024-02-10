package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.JWTClaimsSetAuthenticationManager.JWTClaimsSetAuthenticationManagerResolver;

import reactor.core.publisher.Mono;

/**
 * <p>
 * An {@link ReactiveAuthenticationManagerResolver} always resolving the same {@link ReactiveJWTClaimsSetAuthenticationManager} which relies on
 * {@link JWTClaimsSetAuthenticationManagerResolver}, itself using {@link SpringAddonsReactiveJwtDecoderFactory} and a {@link Converter Converter@lt;Jwt,
 * AbstractAuthenticationToken&gt;}.
 * </p>
 * <p>
 * {@link DefaultSpringAddonsReactiveJwtDecoderFactory}, the default {@link SpringAddonsReactiveJwtDecoderFactory} throws an exception if the OpenID Provider
 * configuration properties could not be resolved from the JWT claims.
 * </p>
 * 
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class SpringAddonsReactiveJwtAuthenticationManagerResolver implements ReactiveAuthenticationManagerResolver<ServerWebExchange> {
    private final ReactiveJWTClaimsSetAuthenticationManager authenticationManager;

    public SpringAddonsReactiveJwtAuthenticationManagerResolver(
            OpenidProviderPropertiesResolver opPropertiesResolver,
            SpringAddonsReactiveJwtDecoderFactory jwtDecoderFactory,
            Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter) {
        authenticationManager = new ReactiveJWTClaimsSetAuthenticationManager(opPropertiesResolver, jwtDecoderFactory, jwtAuthenticationConverter);
    }

    @Override
    public Mono<ReactiveAuthenticationManager> resolve(ServerWebExchange context) {
        return Mono.just(authenticationManager);
    }
}
