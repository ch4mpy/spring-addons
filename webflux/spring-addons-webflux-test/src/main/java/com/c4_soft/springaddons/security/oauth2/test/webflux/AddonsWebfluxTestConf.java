package com.c4_soft.springaddons.security.oauth2.test.webflux;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.config.Customizer.withDefaults;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.reactive.ResourceServerAuthorizeExchangeSpecPostProcessor;
import com.c4_soft.springaddons.security.oauth2.config.reactive.ResourceServerHttpSecurityPostProcessor;

import reactor.core.publisher.Mono;

@TestConfiguration
@Import({ WebTestClientProperties.class })
public class AddonsWebfluxTestConf {

	@MockBean
	ReactiveJwtDecoder jwtDecoder;

	@MockBean
	ReactiveAuthenticationManagerResolver<ServerWebExchange> jwtIssuerReactiveAuthenticationManagerResolver;

	@MockBean
	ReactiveOpaqueTokenIntrospector introspector;

	@ConditionalOnMissingBean
	@Bean
	InMemoryReactiveClientRegistrationRepository clientRegistrationRepository() {
		final var clientRegistrationRepository = mock(InMemoryReactiveClientRegistrationRepository.class);
		when(clientRegistrationRepository.iterator()).thenReturn(new ArrayList<ClientRegistration>().iterator());
		when(clientRegistrationRepository.spliterator()).thenReturn(new ArrayList<ClientRegistration>().spliterator());
		return clientRegistrationRepository;
	}

	@MockBean
	ReactiveOAuth2AuthorizedClientService oAuth2AuthorizedClientService;

	@Bean
	HttpSecurity httpSecurity() {
		return mock(HttpSecurity.class);
	}

	@Bean
	@Scope("prototype")
	WebTestClientSupport webTestClientSupport(
			WebTestClientProperties webTestClientProperties,
			WebTestClient webTestClient,
			SpringAddonsSecurityProperties addonsProperties) {
		return new WebTestClientSupport(webTestClientProperties, webTestClient, addonsProperties);
	}

	@ConditionalOnMissingBean
	@Bean
	OAuth2AuthoritiesConverter authoritiesConverter() {
		return mock(OAuth2AuthoritiesConverter.class);
	}

	@ConditionalOnMissingBean
	@Bean
	ServerAccessDeniedHandler serverAccessDeniedHandler() {
		return (var exchange, var ex) -> exchange.getPrincipal().flatMap(principal -> {
			var response = exchange.getResponse();
			response.setStatusCode(principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
			response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
			var dataBufferFactory = response.bufferFactory();
			var buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
			return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
		});
	}

	@ConditionalOnMissingBean
	@Bean
	SecurityWebFilterChain springAddonsResourceServerSecurityFilterChain(
			ServerHttpSecurity http,
			ServerAccessDeniedHandler accessDeniedHandler,
			SpringAddonsSecurityProperties addonsProperties,
			ServerProperties serverProperties,
			ResourceServerAuthorizeExchangeSpecPostProcessor authorizePostProcessor,
			ResourceServerHttpSecurityPostProcessor httpPostProcessor,
			CorsConfigurationSource corsConfigurationSource)
			throws Exception {

		if (addonsProperties.getCors().length > 0) {
			http.cors(cors -> cors.configurationSource(corsConfigurationSource));
		} else {
			http.cors(cors -> cors.disable());
		}

		switch (addonsProperties.getCsrf()) {
		case DISABLE:
			http.csrf(csrf -> csrf.disable());
			break;
		case DEFAULT:
			if (addonsProperties.isStatlessSessions()) {
				http.csrf(csrf -> csrf.disable());
			} else {
				http.csrf(withDefaults());
			}
			break;
		case SESSION:
			break;
		case COOKIE_HTTP_ONLY:
			http.csrf(csrf -> csrf.csrfTokenRepository(new CookieServerCsrfTokenRepository()));
			break;
		case COOKIE_ACCESSIBLE_FROM_JS:
			http.csrf(
					csrf -> csrf.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
							.csrfTokenRequestHandler(new XorServerCsrfTokenRequestAttributeHandler()::handle));
			break;
		}

		if (addonsProperties.isStatlessSessions()) {
			http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
		}

		if (!addonsProperties.isRedirectToLoginIfUnauthorizedOnRestrictedContent()) {
			http.exceptionHandling(exceptionHandling -> exceptionHandling.accessDeniedHandler(accessDeniedHandler));
		}

		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.redirectToHttps(withDefaults());
		}

		http.authorizeExchange(
				authorizeExchange -> authorizePostProcessor.authorizeHttpRequests(authorizeExchange.pathMatchers(addonsProperties.getPermitAll()).permitAll()));

		return httpPostProcessor.process(http).build();
	}

	@ConditionalOnMissingBean
	@Bean
	ResourceServerAuthorizeExchangeSpecPostProcessor authorizePostProcessor() {
		return (ServerHttpSecurity.AuthorizeExchangeSpec spec) -> spec.anyExchange().authenticated();
	}

	@ConditionalOnMissingBean
	@Bean
	ResourceServerHttpSecurityPostProcessor httpPostProcessor() {
		return serverHttpSecurity -> serverHttpSecurity;
	}

	@ConditionalOnMissingBean
	@Bean
	CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties addonsProperties) {
		final var source = new UrlBasedCorsConfigurationSource();
		for (final var corsProps : addonsProperties.getCors()) {
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