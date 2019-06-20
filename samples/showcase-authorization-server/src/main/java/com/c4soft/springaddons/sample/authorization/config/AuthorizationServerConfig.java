/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.c4soft.springaddons.sample.authorization.config;

import java.security.KeyPair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@EnableAuthorizationServer
@Configuration
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	AuthenticationManager authenticationManager;
	KeyPair keyPair;
	boolean jwtEnabled;

	@Autowired
	public AuthorizationServerConfig(
			AuthenticationConfiguration authenticationConfiguration,
			@Value("${showcase.jwt}") boolean jwtEnabled,
			@Nullable KeyPair keyPair) throws Exception {

		this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
		this.keyPair = keyPair;
		this.jwtEnabled = jwtEnabled;
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients)
			throws Exception {
		// @formatter:off
		clients.inMemory()
			.withClient("user-agent")
				.authorizedGrantTypes("password", "refresh_token")
				.secret("{noop}secret")
				.scopes("showcase")
				.accessTokenValiditySeconds(3600)
				.and()
			.withClient("showcase-resource-server")
				.authorizedGrantTypes("client_credentials")
				.secret("{noop}secret")
				.scopes("showcase")
				.authorities("INTROSPECTION_CLIENT")
				.accessTokenValiditySeconds(3600)
				.refreshTokenValiditySeconds(1209600)
				.autoApprove("showcase")
				.and()
			.withClient("actuator")
				.secret("{noop}secret")
				.authorities("ACTUATOR")
				.and();
		// @formatter:on
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		// @formatter:off
		endpoints
			.authenticationManager(authenticationManager)
			.tokenStore(tokenStore());

		if (jwtEnabled) {
			endpoints
				.accessTokenConverter(accessTokenConverter());
		}
		// @formatter:on
	}

	@Bean
	public TokenStore tokenStore() {
		return jwtEnabled ? new JwtTokenStore(accessTokenConverter()) : new InMemoryTokenStore();
	}

	@Bean
	@ConditionalOnProperty("showcase.jwt")
	public JwtAccessTokenConverter accessTokenConverter() {
		final var converter = new JwtAccessTokenConverter();
		converter.setKeyPair(keyPair);

		final DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
		accessTokenConverter.setUserTokenConverter(new SubjectAttributeUserTokenConverter());
		converter.setAccessTokenConverter(accessTokenConverter);

		return converter;
	}


}