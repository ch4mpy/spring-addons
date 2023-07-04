package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.util.Collection;
import java.util.Map;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.ClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.JwtAbstractAuthenticationTokenConverter;
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
	 * Retrieves granted authorities from the Jwt (from its private claims or with the help of an external service)
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
	 * Converter bean from {@link Jwt} to {@link AbstractAuthenticationToken}
	 *
	 * @param  authoritiesConverter  converts access-token claims into Spring authorities
	 * @param  securityProperties    Spring "spring.security" configuration properties
	 * @param  authenticationFactory builds an {@link Authentication} instance from access-token string and claims
	 * @return                       a converter from {@link Jwt} to {@link AbstractAuthenticationToken}
	 */
	@ConditionalOnMissingBean
	@Bean
	JwtAbstractAuthenticationTokenConverter jwtAuthenticationConverter(
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
			SpringAddonsSecurityProperties addonsProperties) {
		return jwt -> new JwtAuthenticationToken(
				jwt,
				authoritiesConverter.convert(jwt.getClaims()),
				new OpenidClaimSet(jwt.getClaims(), addonsProperties.getIssuerProperties(jwt.getIssuer()).getUsernameClaim()).getName());
	}
}