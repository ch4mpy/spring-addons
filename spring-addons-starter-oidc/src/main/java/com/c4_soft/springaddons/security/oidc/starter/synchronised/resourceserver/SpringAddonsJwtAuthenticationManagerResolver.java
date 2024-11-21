package com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.Jwt;

import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.JWTClaimsSetAuthenticationManager.JWTClaimsSetAuthenticationManagerResolver;

import jakarta.servlet.http.HttpServletRequest;

/**
 * <p>
 * An {@link AuthenticationManagerResolver} always resolving the same {@link JWTClaimsSetAuthenticationManager} which relies on
 * {@link JWTClaimsSetAuthenticationManagerResolver}, itself using {@link SpringAddonsJwtDecoderFactory} and a {@link Converter Converter@lt;Jwt,
 * AbstractAuthenticationToken&gt;}.
 * </p>
 * <p>
 * {@link DefaultSpringAddonsJwtDecoderFactory}, the default {@link SpringAddonsJwtDecoderFactory} throws an exception if the OpenID Provider configuration
 * properties could not be resolved from the JWT claims.
 * </p>
 * 
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SpringAddonsJwtAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {
    private final JWTClaimsSetAuthenticationManager authenticationManager;

    public SpringAddonsJwtAuthenticationManagerResolver(
            OpenidProviderPropertiesResolver opPropertiesResolver,
            SpringAddonsJwtDecoderFactory jwtDecoderFactory,
            Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter) {
        this.authenticationManager = new JWTClaimsSetAuthenticationManager(opPropertiesResolver, jwtDecoderFactory, jwtAuthenticationConverter);
    }

    @Override
    public AuthenticationManager resolve(HttpServletRequest context) {
        return authenticationManager;
    }
}
