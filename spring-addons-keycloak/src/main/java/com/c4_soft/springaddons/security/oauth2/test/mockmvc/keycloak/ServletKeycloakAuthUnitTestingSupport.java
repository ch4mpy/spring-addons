/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */

package com.c4_soft.springaddons.security.oauth2.test.mockmvc.keycloak;

import java.util.Optional;

import org.keycloak.representations.adapters.config.AdapterConfig;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Import(ServletKeycloakAuthUnitTestingSupport.UnitTestConfig.class)
public class ServletKeycloakAuthUnitTestingSupport {

	@Autowired
	BeanFactory beanFactory;

	public KeycloakAuthRequestPostProcessor authentication() {
		return beanFactory.getBean(KeycloakAuthRequestPostProcessor.class);
	}

	@TestConfiguration(proxyBeanMethods = false)
	public static class UnitTestConfig {

		@Bean
		@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
		KeycloakAuthRequestPostProcessor keycloakAuthRequestPostProcessor(Optional<GrantedAuthoritiesMapper> authoritiesMapper) {
			return new KeycloakAuthRequestPostProcessor(authoritiesMapper);
		}

		@Bean
		AdapterConfig adapterConfig() {
			final AdapterConfig conf = new AdapterConfig();
			conf.setRealm("junit");
			conf.setResource("unit-tests");
			conf.setAuthServerUrl("https://localhost");
			return conf;
		}
	}

}
