package com.c4_soft.springaddons.security.oauth2.test.webflux;

import static org.mockito.Mockito.mock;

import java.nio.charset.Charset;
import java.util.Arrays;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.CsrfSpec;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import com.c4_soft.springaddons.security.oauth2.ClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.ClaimSet2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

import reactor.core.publisher.Mono;

@TestConfiguration
@Import({ WebTestClientProperties.class, SpringAddonsSecurityProperties.class })
public class AddonsWebfluxTestConf {

	@Bean
	HttpSecurity httpSecurity() {
		return mock(HttpSecurity.class);
	}

	@Bean
	@Scope("prototype")
	public WebTestClientSupport webTestClientSupport(
			WebTestClientProperties webTestClientProperties,
			WebTestClient webTestClient,
			SpringAddonsSecurityProperties securityProperties) {
		return new WebTestClientSupport(webTestClientProperties, webTestClient, securityProperties);
	}

	@ConditionalOnMissingBean
	@Bean
	ClaimSet2AuthoritiesConverter<ClaimSet> authoritiesConverter() {
		return mock(ClaimSet2AuthoritiesConverter.class);
	}

	@ConditionalOnMissingBean
	@Bean
	ServerAccessDeniedHandler serverAccessDeniedHandler() {
		return (var exchange, var ex) -> exchange.getPrincipal().flatMap(principal -> {
			final var response = exchange.getResponse();
			response.setStatusCode(principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
			response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
			final var dataBufferFactory = response.bufferFactory();
			final var buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
			return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
		});
	}

	@ConditionalOnMissingBean
	@Bean
	SecurityWebFilterChain filterChain(
			ServerHttpSecurity http,
			ServerAccessDeniedHandler accessDeniedHandler,
			SpringAddonsSecurityProperties securityProperties,
			ServerProperties serverProperties)
			throws Exception {

		if (securityProperties.getPermitAll().length > 0) {
			http.anonymous();
		}

		if (securityProperties.getCors().length > 0) {
			http.cors().configurationSource(corsConfigurationSource(securityProperties));
		}

		if (securityProperties.isCsrfEnabled()) {
			final CsrfSpec configurer = http.csrf();
			if (securityProperties.isStatlessSessions()) {
				configurer.csrfTokenRepository(new CookieServerCsrfTokenRepository());
			}
		} else {
			http.csrf().disable();
		}

		if (securityProperties.isStatlessSessions()) {
			http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
		}

		if (!securityProperties.isRedirectToLoginIfUnauthorizedOnRestrictedContent()) {
			http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
		}

		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.redirectToHttps();
		}

		http.authorizeExchange().pathMatchers(securityProperties.getPermitAll()).permitAll();

		return http.build();
	}

	private CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties securityProperties) {
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		for (final SpringAddonsSecurityProperties.CorsProperties corsProps : securityProperties.getCors()) {
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