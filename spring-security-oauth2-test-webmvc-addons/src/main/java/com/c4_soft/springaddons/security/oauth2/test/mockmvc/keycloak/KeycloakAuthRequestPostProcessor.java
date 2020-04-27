/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.c4_soft.springaddons.security.oauth2.test.mockmvc.keycloak;

import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import com.c4_soft.springaddons.security.oauth2.test.keycloak.KeycloakAuthenticationTokenTestingBuilder;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AuthenticationRequestPostProcessor;

public class KeycloakAuthRequestPostProcessor
		extends
		KeycloakAuthenticationTokenTestingBuilder<KeycloakAuthRequestPostProcessor>
		implements
		AuthenticationRequestPostProcessor<KeycloakAuthenticationToken> {

	@Autowired
	public KeycloakAuthRequestPostProcessor(GrantedAuthoritiesMapper authoritiesMapper) {
		super(authoritiesMapper);
	}

}