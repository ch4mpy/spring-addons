package com.c4_soft.springaddons.security.oauth2.config;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.SupplierJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2OidcTokenConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.CorsProperties;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;
import com.c4_soft.springaddons.security.oauth2.oidc.SynchronizedJwt2OidcAuthenticationConverter;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ServletSecurityBeans {
	private final OAuth2ResourceServerProperties auth2ResourceServerProperties;
	private final SpringAddonsSecurityProperties securityProperties;

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
		return new SynchronizedEmbeddedJwt2GrantedAuthoritiesConverter(securityProperties);
	}

	@ConditionalOnMissingBean
	@Bean
	public SynchronizedJwt2OidcTokenConverter<OidcToken> tokenConverter() {
		return (Jwt jwt) -> new OidcToken(jwt.getClaims());
	}

	@ConditionalOnMissingBean
	@Bean
	public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
		final Set<String> locations =
				Stream
						.concat(
								Stream
										.of(
												Optional
														.of(auth2ResourceServerProperties.getJwt())
														.map(
																org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt::getIssuerUri)
														.orElse(null)),
								Stream.of(securityProperties.getAuthorizationServerLocations()))
						.filter(l -> l != null && l.length() > 0)
						.collect(Collectors.toSet());
		final Map<String, AuthenticationManager> managers = locations.stream().collect(Collectors.toMap(l -> l, l -> {
			final JwtDecoder decoder = new SupplierJwtDecoder(() -> JwtDecoders.fromIssuerLocation(l));
			final JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
			provider.setJwtAuthenticationConverter(authenticationConverter(authoritiesConverter(), tokenConverter()));
			return provider::authenticate;
		}));
		return new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver<String>) managers::get);
	}

	@ConditionalOnMissingBean
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		for (final CorsProperties corsProps : securityProperties.getCors()) {
			final CorsConfiguration configuration = new CorsConfiguration();
			configuration.setAllowedOrigins(Arrays.asList(corsProps.getAllowedOrigins()));
			configuration.setAllowedMethods(Arrays.asList(corsProps.getAllowedMethods()));
			configuration.setAllowedHeaders(Arrays.asList(corsProps.getAllowedHeaders()));
			configuration.setExposedHeaders(Arrays.asList(corsProps.getExposedHeaders()));
			source.registerCorsConfiguration(corsProps.getPath(), configuration);
		}
		return source;
	}
}