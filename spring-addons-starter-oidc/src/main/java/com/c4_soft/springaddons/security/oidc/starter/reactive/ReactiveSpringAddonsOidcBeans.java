package com.c4_soft.springaddons.security.oidc.starter.reactive;

import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;

import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.c4_soft.springaddons.security.oidc.starter.ClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultGrantedAuthoritiesMapperCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultJwtAbstractAuthenticationTokenConverterCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultOpaqueTokenAuthenticationConverterCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsNotServlet;
import com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver.ReactiveJwtAbstractAuthenticationTokenConverter;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Conditional(IsNotServlet.class)
@AutoConfiguration
@ImportAutoConfiguration(SpringAddonsOidcProperties.class)
@Slf4j
public class ReactiveSpringAddonsOidcBeans {

	/**
	 * Retrieves granted authorities from the Jwt (from its private claims or with the help of an external service)
	 *
	 * @param  securityProperties
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	ClaimSetAuthoritiesConverter authoritiesConverter(SpringAddonsOidcProperties addonsProperties) {
		log.debug("Building default CorsConfigurationSource with: {}", addonsProperties);
		return new ConfigurableClaimSetAuthoritiesConverter(addonsProperties);
	}

	/**
	 * Converter bean from {@link Jwt} to {@link AbstractAuthenticationToken}
	 *
	 * @param  authoritiesConverter  converts access-token claims into Spring authorities
	 * @param  authenticationFactory builds an {@link Authentication} instance from access-token string and claims
	 * @return                       a converter from {@link Jwt} to {@link AbstractAuthenticationToken}
	 */
	@Conditional(DefaultJwtAbstractAuthenticationTokenConverterCondition.class)
	@Bean
	ReactiveJwtAbstractAuthenticationTokenConverter jwtAuthenticationConverter(
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
			SpringAddonsOidcProperties addonsProperties) {
		return jwt -> Mono.just(
				new JwtAuthenticationToken(
						jwt,
						authoritiesConverter.convert(jwt.getClaims()),
						new OpenidClaimSet(jwt.getClaims(), addonsProperties.getOpProperties(jwt.getIssuer()).getUsernameClaim()).getName()));
	}

	/**
	 * Converter bean from successful introspection result to {@link Authentication} instance
	 *
	 * @param  authoritiesConverter  converts access-token claims into Spring authorities
	 * @param  authenticationFactory builds an {@link Authentication} instance from access-token string and claims
	 * @return                       a converter from successful introspection result to {@link Authentication} instance
	 */
	@Conditional(DefaultOpaqueTokenAuthenticationConverterCondition.class)
	@Bean
	@SuppressWarnings("unchecked")
	ReactiveOpaqueTokenAuthenticationConverter introspectionAuthenticationConverter(
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
			SpringAddonsOidcProperties addonsProperties,
			OAuth2ResourceServerProperties resourceServerProperties) {
		return (String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) -> Mono.just(
				new BearerTokenAuthentication(
						new OAuth2IntrospectionAuthenticatedPrincipal(
								new OpenidClaimSet(
										authenticatedPrincipal.getAttributes(),
										Stream.of(addonsProperties.getOps())
												.filter(
														issProps -> resourceServerProperties.getOpaquetoken().getIntrospectionUri()
																.contains(issProps.getIss().toString()))
												.findAny().orElse(addonsProperties.getOps()[0]).getUsernameClaim()).getName(),
								authenticatedPrincipal.getAttributes(),
								(Collection<GrantedAuthority>) authenticatedPrincipal.getAuthorities()),
						new OAuth2AccessToken(
								OAuth2AccessToken.TokenType.BEARER,
								introspectedToken,
								Instant.ofEpochSecond(((Integer) authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.IAT)).longValue()),
								Instant.ofEpochSecond(((Integer) authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.EXP)).longValue())),
						authoritiesConverter.convert(authenticatedPrincipal.getAttributes())));
	}

	/**
	 * @param  authoritiesConverter the authorities converter to use (by default {@link ConfigurableClaimSetAuthoritiesConverter})
	 * @return                      {@link GrantedAuthoritiesMapper} using the authorities converter in the context
	 */
	@Conditional(DefaultGrantedAuthoritiesMapperCondition.class)
	@ConditionalOnMissingBean
	@Bean
	GrantedAuthoritiesMapper grantedAuthoritiesMapper(Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
		return (authorities) -> {
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

			authorities.forEach(authority -> {
				if (authority instanceof OidcUserAuthority oidcAuth) {
					mappedAuthorities.addAll(authoritiesConverter.convert(oidcAuth.getIdToken().getClaims()));

				} else if (authority instanceof OAuth2UserAuthority oauth2Auth) {
					mappedAuthorities.addAll(authoritiesConverter.convert(oauth2Auth.getAttributes()));

				}
			});

			return mappedAuthorities;
		};
	}
}