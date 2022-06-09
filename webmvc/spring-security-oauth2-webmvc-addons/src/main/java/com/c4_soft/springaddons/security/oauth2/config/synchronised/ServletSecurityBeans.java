package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.SupplierJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2OidcAuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2OidcTokenConverter;
import com.c4_soft.springaddons.security.oauth2.config.JwtGrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SimpleJwtGrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.TokenIssuerProperties;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;

import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * <b>Usage</b><br>
 * If not using spring-boot, &#64;Import or &#64;ComponentScan this class. All beans defined here are &#64;ConditionalOnMissingBean => just
 * define your own &#64;Beans to override.
 * </p>
 * <p>
 * <b>Provided &#64;Beans</b>
 * </p>
 * <ul>
 * <li><b>SecurityFilterChain</b>: applies CORS, CSRF, anonymous, sessionCreationPolicy, SSL redirect and 401 instead of redirect to login
 * properties as defined in {@link SpringAddonsSecurityProperties}</li>
 * <li><b>ExpressionInterceptUrlRegistryPostProcessor</b>. Override if you need fined grained HTTP security (more than authenticated() to
 * all routes but the ones defined as permitAll() in {@link SpringAddonsSecurityProperties}</li>
 * <li><b>SimpleJwtGrantedAuthoritiesConverter</b>: responsible for converting the JWT into Collection&lt;? extends
 * GrantedAuthority&gt;</li>
 * <li><b>SynchronizedJwt2OidcTokenConverter&lt;OidcToken&gt;</b>: responsible for converting the JWT into OidcToken</li>
 * <li><b>SynchronizedJwt2AuthenticationConverter&lt;OidcAuthentication&lt;T&gt;&gt;</b>: responsible for converting the JWT into an
 * Authentication (uses both beans above)</li>
 * <li><b>JwtIssuerAuthenticationManagerResolver</b>: required to be able to define more than one token issuer until
 * https://github.com/spring-projects/spring-boot/issues/30108 is solved</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp@c4-soft.com
 */
@AutoConfiguration
@Import({ SpringAddonsSecurityProperties.class })
@EnableWebSecurity
@Slf4j
public class ServletSecurityBeans {

	@ConditionalOnMissingBean
	@Bean
	public SecurityFilterChain filterChain(
			HttpSecurity http,
			AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver,
			ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor,
			ServerProperties serverProperties,
			SpringAddonsSecurityProperties securityProperties)
			throws Exception {
		http.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver));

		if (securityProperties.isAnonymousEnabled()) {
			http.anonymous();
		}

		if (securityProperties.getCors().length > 0) {
			http.cors().configurationSource(corsConfigurationSource(securityProperties));
		}

		if (!securityProperties.isCsrfEnabled()) {
			http.csrf().disable();
		}

		if (securityProperties.isStatlessSessions()) {
			http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		}

		if (!securityProperties.isRedirectToLoginIfUnauthorizedOnRestrictedContent()) {
			http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
				response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
				response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
			});
		}

		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.requiresChannel().anyRequest().requiresSecure();
		} else {
			http.requiresChannel().anyRequest().requiresInsecure();
		}

		expressionInterceptUrlRegistryPostProcessor.authorizeRequests(http.authorizeRequests().antMatchers(securityProperties.getPermitAll()).permitAll());

		return http.build();
	}

	@ConditionalOnMissingBean
	@Bean
	public ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
		return registry -> registry.anyRequest().authenticated();
	}

	@ConditionalOnMissingBean
	@Bean
	public <T extends OidcToken> SynchronizedJwt2AuthenticationConverter<OidcAuthentication<T>> authenticationConverter(
			JwtGrantedAuthoritiesConverter authoritiesConverter,
			SynchronizedJwt2OidcTokenConverter<T> tokenConverter) {
		log.debug("Building default SynchronizedJwt2OidcAuthenticationConverter");
		return new SynchronizedJwt2OidcAuthenticationConverter<>(authoritiesConverter, tokenConverter);
	}

	@ConditionalOnMissingBean
	@Bean
	public JwtGrantedAuthoritiesConverter authoritiesConverter(SpringAddonsSecurityProperties securityProperties) {
		log.debug("Building default SimpleJwtGrantedAuthoritiesConverter with: {}", securityProperties);
		return new SimpleJwtGrantedAuthoritiesConverter(securityProperties);
	}

	@ConditionalOnMissingBean
	@Bean
	public SynchronizedJwt2OidcTokenConverter<OidcToken> tokenConverter() {
		log.debug("Building default SynchronizedJwt2OidcTokenConverter");
		return (var jwt) -> new OidcToken(jwt.getClaims());
	}

	@ConditionalOnMissingBean
	@Bean
	public JwtIssuerAuthenticationManagerResolver authenticationManagerResolver(
			OAuth2ResourceServerProperties auth2ResourceServerProperties,
			SpringAddonsSecurityProperties securityProperties,
			Converter<Jwt, ? extends AbstractAuthenticationToken> authenticationConverter) {
		final var locations =
				Stream
						.concat(
								Optional
										.of(auth2ResourceServerProperties.getJwt())
										.map(org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt::getIssuerUri)
										.stream(),
								Stream.of(securityProperties.getTokenIssuers()).map(TokenIssuerProperties::getLocation))
						.filter(Objects::nonNull)
						.map(Serializable::toString)
						.filter(StringUtils::hasLength)
						.collect(Collectors.toSet());
		final Map<String, AuthenticationManager> managers = locations.stream().collect(Collectors.toMap(l -> l, l -> {
			final JwtDecoder decoder = new SupplierJwtDecoder(() -> JwtDecoders.fromIssuerLocation(l));
			final var provider = new JwtAuthenticationProvider(decoder);
			provider.setJwtAuthenticationConverter(authenticationConverter);
			return provider::authenticate;
		}));
		log
				.debug(
						"Building default JwtIssuerAuthenticationManagerResolver with: ",
						auth2ResourceServerProperties.getJwt(),
						Stream.of(securityProperties.getTokenIssuers()).toList());
		return new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver<String>) managers::get);
	}

	private CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties securityProperties) {
		log.debug("Building default CorsConfigurationSource with: {}", Stream.of(securityProperties.getCors()).toList());
		final var source = new UrlBasedCorsConfigurationSource();
		for (final var corsProps : securityProperties.getCors()) {
			final var configuration = new CorsConfiguration();
			configuration.setAllowedOrigins(Arrays.asList(corsProps.getAllowedOrigins()));
			configuration.setAllowedMethods(Arrays.asList(corsProps.getAllowedMethods()));
			configuration.setAllowedHeaders(Arrays.asList(corsProps.getAllowedHeaders()));
			configuration.setExposedHeaders(Arrays.asList(corsProps.getExposedHeaders()));
			source.registerCorsConfiguration(corsProps.getPath(), configuration);
		}
		return source;
	}
}