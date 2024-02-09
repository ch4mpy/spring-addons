package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import java.net.URI;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.util.Assert;

import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.properties.NotAConfiguredOpenidProviderException;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.JWTClaimsSetAuthenticationManager.JWTClaimsSetAuthenticationManagerResolver;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

/**
 * <p>
 * An {@link AuthenticationManager} relying on {@link JWTClaimsSetAuthenticationManagerResolver}, itself using {@link SpringAddonsReactiveJwtDecoderFactory} and
 * a {@link Converter Converter&lt;Jwt, Mono&lt;? extends AbstractAuthenticationToken&gt;&gt;}.
 * </p>
 * <p>
 * {@link DefaultSpringAddonsReactiveJwtDecoderFactory}, the default {@link SpringAddonsReactiveJwtDecoderFactory} throws an exception if the OpenID Provider
 * configuration properties could not be resolved from the JWT claims.
 * </p>
 * 
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class ReactiveJWTClaimsSetAuthenticationManager implements ReactiveAuthenticationManager {

    private final ReactiveJWTClaimsSetAuthenticationManagerResolver jwtAuthenticationManagerResolver;

    public ReactiveJWTClaimsSetAuthenticationManager(
            OpenidProviderPropertiesResolver opPropertiesResolver,
            SpringAddonsReactiveJwtDecoderFactory jwtDecoderFactory,
            Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter) {
        this.jwtAuthenticationManagerResolver = new ReactiveJWTClaimsSetAuthenticationManagerResolver(
            opPropertiesResolver,
            jwtDecoderFactory,
            jwtAuthenticationConverter);
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isTrue(authentication instanceof BearerTokenAuthenticationToken, "Authentication must be of type BearerTokenAuthenticationToken");
        JWTClaimsSet jwtClaimSet;
        try {
            jwtClaimSet = JWTParser.parse(((BearerTokenAuthenticationToken) authentication).getToken()).getJWTClaimsSet();
        } catch (ParseException e) {
            throw new InvalidBearerTokenException("Could not retrieve JWT claim-set");
        }
        return this.jwtAuthenticationManagerResolver.resolve(jwtClaimSet).flatMap(authenticationManager -> {
            if (authenticationManager == null) {
                throw new InvalidBearerTokenException("Could not resolve the Authentication manager for the provided JWT");
            }
            return authenticationManager.authenticate(authentication);
        });
    }

    /**
     * <p>
     * An {@link ReactiveAuthenticationManagerResolver} for resource servers using JWT decoder(s). It relies on a {@link SpringAddonsReactiveJwtDecoderFactory}
     * and a {@link Converter Converter&lt;Jwt, Mono&lt;? extends AbstractAuthenticationToken&gt;&gt;}
     * </p>
     * <p>
     * {@link DefaultSpringAddonsReactiveJwtDecoderFactory}, the default {@link SpringAddonsReactiveJwtDecoderFactory} throws an exception if the OpenID
     * Provider configuration properties could not be resolved from the JWT claims.
     * </p>
     *
     * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
     */
    @RequiredArgsConstructor
    public static class ReactiveJWTClaimsSetAuthenticationManagerResolver implements ReactiveAuthenticationManagerResolver<JWTClaimsSet> {

        private final OpenidProviderPropertiesResolver opPropertiesResolver;
        private final SpringAddonsReactiveJwtDecoderFactory jwtDecoderFactory;
        private final Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter;
        private final Map<String, ReactiveAuthenticationManager> jwtManagers = new ConcurrentHashMap<>();

        @Override
        public Mono<ReactiveAuthenticationManager> resolve(JWTClaimsSet jwt) {
            final var issuer = jwt.getIssuer();
            if (!jwtManagers.containsKey(issuer)) {
                final var opProperties = opPropertiesResolver
                    .resolve(jwt.getClaims())
                    .orElseThrow(() -> new NotAConfiguredOpenidProviderException(jwt.getClaims()));

                final var decoder = jwtDecoderFactory
                    .create(
                        Optional.ofNullable(opProperties.getJwkSetUri()),
                        Optional.of(URI.create(jwt.getIssuer().toString())),
                        Optional.of(opProperties.getAud()));

                var provider = new JwtReactiveAuthenticationManager(decoder);
                provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
                jwtManagers.put(issuer, provider::authenticate);
            }
            return Mono.just(jwtManagers.get(issuer));
        }
    }

}
