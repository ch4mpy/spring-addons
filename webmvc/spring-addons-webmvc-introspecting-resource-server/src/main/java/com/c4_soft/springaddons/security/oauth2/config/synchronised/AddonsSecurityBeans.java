package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;

import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.ClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

import lombok.extern.slf4j.Slf4j;

/**
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@AutoConfiguration
@Slf4j
@Import({ SpringAddonsSecurityProperties.class })
public class AddonsSecurityBeans {

	/**
	 * Retrieves granted authorities from the introspected token attributes, according to configuration set for the issuer set in this attributes
	 *
	 * @param  securityProperties
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	ClaimSetAuthoritiesConverter authoritiesConverter(SpringAddonsSecurityProperties addonsProperties) {
		log.debug("Building default SimpleJwtGrantedAuthoritiesConverter with: {}", addonsProperties);
		return new ConfigurableClaimSetAuthoritiesConverter(addonsProperties);
	}

	/**
	 * Converter bean from successful introspection result to an {@link Authentication} instance
	 *
	 * @param  authoritiesConverter  converts access-token claims into Spring authorities
	 * @param  authenticationFactory builds an {@link Authentication} instance from access-token string and claims
	 * @return                       a converter from successful introspection result to an {@link Authentication} instance
	 */
	@SuppressWarnings("unchecked")
	@ConditionalOnMissingBean
	@Bean
	OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter(
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
			SpringAddonsSecurityProperties addonsProperties,
			OAuth2ResourceServerProperties resourceServerProperties) {
		return (String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) -> {
			return new BearerTokenAuthentication(
					new OAuth2IntrospectionAuthenticatedPrincipal(
							new OpenidClaimSet(
									authenticatedPrincipal.getAttributes(),
									Stream.of(addonsProperties.getIssuers())
											.filter(
													issProps -> resourceServerProperties.getOpaquetoken().getIntrospectionUri()
															.contains(issProps.getLocation().toString()))
											.findAny().orElse(addonsProperties.getIssuers()[0]).getUsernameClaim()).getName(),
							authenticatedPrincipal.getAttributes(),
							(Collection<GrantedAuthority>) authenticatedPrincipal.getAuthorities()),
					new OAuth2AccessToken(
							OAuth2AccessToken.TokenType.BEARER,
							introspectedToken,
							Instant.ofEpochSecond(((Integer) authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.IAT)).longValue()),
							Instant.ofEpochSecond(((Integer) authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.EXP)).longValue())),
					authoritiesConverter.convert(authenticatedPrincipal.getAttributes()));
		};
	}
}