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

import org.springframework.beans.factory.ObjectFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.test.support.web.SerializationHelper;

import jakarta.servlet.http.HttpServletRequest;

/**
 * @author ch4mp Test configuration to mock JwtDecoder
 */
@AutoConfiguration
@Import({ MockMvcProperties.class, AuthenticationFactoriesTestConf.class })
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

}
