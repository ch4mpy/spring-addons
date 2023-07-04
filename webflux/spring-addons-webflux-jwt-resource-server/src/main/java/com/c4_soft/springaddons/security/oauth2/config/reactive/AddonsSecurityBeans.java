package com.c4_soft.springaddons.security.oauth2.config.reactive;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.ClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.ReactiveJwtAbstractAuthenticationTokenConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@AutoConfiguration
@Slf4j
@ImportAutoConfiguration(SpringAddonsSecurityProperties.class)
public class AddonsSecurityBeans {

	/**
	 * Retrieves granted authorities from the Jwt (from its private claims or with the help of an external service)
	 *
	 * @param  securityProperties
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	ClaimSetAuthoritiesConverter authoritiesConverter(SpringAddonsSecurityProperties addonsProperties) {
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
	@ConditionalOnMissingBean
	@Bean
	ReactiveJwtAbstractAuthenticationTokenConverter
			jwtAuthenticationConverter(ClaimSetAuthoritiesConverter authoritiesConverter, SpringAddonsSecurityProperties addonsProperties) {
		return jwt -> Mono.just(
				new JwtAuthenticationToken(
						jwt,
						authoritiesConverter.convert(jwt.getClaims()),
						new OpenidClaimSet(jwt.getClaims(), addonsProperties.getIssuerProperties(jwt.getIssuer()).getUsernameClaim()).getName()));
	}
}