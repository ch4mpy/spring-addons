package com.c4_soft.springaddons.security.oauth2.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2OidcTokenConverter;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;
import com.c4_soft.springaddons.security.oauth2.oidc.SynchronizedJwt2OidcAuthenticationConverter;

public class ServletSecurityBeans {
	private final String issuerUri;
	private final SpringAddonsSecurityProperties securityProperties;

	public ServletSecurityBeans(
			@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri,
			SpringAddonsSecurityProperties securityProperties) {
		this.issuerUri = issuerUri;
		this.securityProperties = securityProperties;
	}

	@ConditionalOnMissingBean
	@Bean
	public <T extends OidcToken> SynchronizedJwt2AuthenticationConverter<? extends AbstractAuthenticationToken> authenticationConverter(
			SynchronizedJwt2GrantedAuthoritiesConverter authoritiesConverter,
			SynchronizedJwt2OidcTokenConverter<T> tokenConverter) {
		return new SynchronizedJwt2OidcAuthenticationConverter<>(authoritiesConverter, tokenConverter);
	}

	@ConditionalOnMissingBean
	@Bean
	public SynchronizedJwt2GrantedAuthoritiesConverter authoritiesConverter() {
		return this.securityProperties.getKeycloak() != null && StringUtils.hasLength(this.securityProperties.getKeycloak().getClientId())
				? new KeycloakSynchronizedJwt2GrantedAuthoritiesConverter(securityProperties)
				: new Auth0SynchronizedJwt2GrantedAuthoritiesConverter(securityProperties);
	}

	@ConditionalOnMissingBean
	@Bean
	public SynchronizedJwt2OidcTokenConverter<OidcToken> tokenConverter() {
		return (Jwt jwt) -> new OidcToken(jwt.getClaims());
	}

	@ConditionalOnMissingBean
	@Bean
	public JwtDecoder jwtDecoder() {
		return JwtDecoders.fromOidcIssuerLocation(issuerUri);
	}

	@ConditionalOnMissingBean
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		final CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList(securityProperties.getCors().getAllowedOrigins()));
		configuration.setAllowedMethods(Arrays.asList(securityProperties.getCors().getAllowedMethods()));
		configuration.setAllowedHeaders(Arrays.asList(securityProperties.getCors().getAllowedHeaders()));
		configuration.setExposedHeaders(Arrays.asList(securityProperties.getCors().getExposedHeaders()));
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		for (final String p : securityProperties.getCors().getPath()) {
			source.registerCorsConfiguration(p, configuration);
		}
		return source;
	}
}