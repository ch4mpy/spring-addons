/*
 * Copyright 2020 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2.test.mockmvc;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;

import org.springframework.beans.factory.ObjectFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ResourceServerHttpSecurityPostProcessor;
import com.c4_soft.springaddons.test.support.web.SerializationHelper;

import jakarta.servlet.http.HttpServletRequest;

/**
 * @author ch4mp Test configuration to mock JwtDecoder
 */
@AutoConfiguration
@Import({ MockMvcProperties.class })
public class AddonsWebmvcTestConf {

	@MockBean
	JwtDecoder jwtDecoder;

	@MockBean
	AuthenticationManagerResolver<HttpServletRequest> jwtIssuerAuthenticationManagerResolver;

	@MockBean
	OpaqueTokenIntrospector introspector;

	@ConditionalOnMissingBean
	@Bean
	InMemoryClientRegistrationRepository clientRegistrationRepository() {
		final var clientRegistrationRepository = mock(InMemoryClientRegistrationRepository.class);
		when(clientRegistrationRepository.iterator()).thenReturn(new ArrayList<ClientRegistration>().iterator());
		when(clientRegistrationRepository.spliterator()).thenReturn(new ArrayList<ClientRegistration>().spliterator());
		return clientRegistrationRepository;
	}

	@MockBean
	OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

	@Bean
	SerializationHelper serializationHelper(ObjectFactory<HttpMessageConverters> messageConverters) {
		return new SerializationHelper(messageConverters);
	}

	@Bean
	@Scope("prototype")
	MockMvcSupport mockMvcSupport(
			MockMvc mockMvc,
			SerializationHelper serializationHelper,
			MockMvcProperties mockMvcProperties,
			ServerProperties serverProperties,
			SpringAddonsSecurityProperties addonsProperties) {
		return new MockMvcSupport(mockMvc, serializationHelper, mockMvcProperties, serverProperties, addonsProperties);
	}

	@ConditionalOnMissingBean
	@Bean
	OAuth2AuthoritiesConverter claimSet2AuthoritiesConverter() {
		return mock(OAuth2AuthoritiesConverter.class);
	}

	@ConditionalOnMissingBean
	@Bean
	SecurityFilterChain resourceServerSecurityFilterChain(
			HttpSecurity http,
			ServerProperties serverProperties,
			SpringAddonsSecurityProperties addonsProperties,
			ExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
			ResourceServerHttpSecurityPostProcessor httpPostProcessor,
			CorsConfigurationSource corsConfigurationSource)
			throws Exception {

		if (addonsProperties.getPermitAll().length > 0) {
			http.anonymous();
		}

		if (addonsProperties.getCors().length > 0) {
			http.cors().configurationSource(corsConfigurationSource);
		} else {
			http.cors().disable();
		}

		switch (addonsProperties.getCsrf()) {
		case DISABLE:
			http.csrf().disable();
			break;
		case DEFAULT:
			if (addonsProperties.isStatlessSessions()) {
				http.csrf().disable();
			} else {
				http.csrf();
			}
			break;
		case SESSION:
			http.csrf();
			break;
		case COOKIE_HTTP_ONLY:
			http.csrf().csrfTokenRepository(new CookieCsrfTokenRepository());
			break;
		case COOKIE_ACCESSIBLE_FROM_JS:
			http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
					.csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler()::handle);
			break;
		}

		if (addonsProperties.isStatlessSessions()) {
			http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		}

		if (!addonsProperties.isRedirectToLoginIfUnauthorizedOnRestrictedContent()) {
			http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
				response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
				response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
			});
		}

		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.requiresChannel().anyRequest().requiresSecure();
		}

		authorizePostProcessor.authorizeHttpRequests(http.authorizeHttpRequests().requestMatchers(addonsProperties.getPermitAll()).permitAll());

		return httpPostProcessor.process(http).build();
	}

	@ConditionalOnMissingBean
	@Bean
	ExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor() {
		return registry -> registry.anyRequest().authenticated();
	}

	@ConditionalOnMissingBean
	@Bean
	ResourceServerHttpSecurityPostProcessor httpPostProcessor() {
		return httpSecurity -> httpSecurity;
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
