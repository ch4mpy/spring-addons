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
package com.c4_soft.springaddons.sample.authorization.config;

import java.security.KeyPair;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
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

	final Environment env;
	final AuthenticationManager authenticationManager;
	final KeyPair keyPair;
	final String actuatorUsername;
	final String actuatorPassword;

	@Autowired
	public AuthorizationServerConfig(
			Environment env,
			AuthenticationConfiguration authenticationConfiguration,
			@Value("${showcase.management.username}") String actuatorUsername,
			@Value("${showcase.management.password}") String actuatorPassword,
			@Nullable KeyPair keyPair) throws Exception {

		this.env = env;
		this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
		this.keyPair = keyPair;
		this.actuatorUsername = actuatorUsername;
		this.actuatorPassword = actuatorPassword;
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
			.withClient(actuatorUsername)
				.secret("{noop}" + actuatorPassword)
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

		if (Stream.of(env.getActiveProfiles()).anyMatch("jwt"::equals)) {
			endpoints
				.accessTokenConverter(accessTokenConverter());
		}
		// @formatter:on
	}

	@Bean
	public TokenStore tokenStore() {
		return Stream.of(env.getActiveProfiles()).anyMatch("jwt"::equals) ?
				new JwtTokenStore(accessTokenConverter()) : new InMemoryTokenStore();
	}

	@Bean
	@Profile("jwt")
	public JwtAccessTokenConverter accessTokenConverter() {
		final var converter = new JwtAccessTokenConverter();
		converter.setKeyPair(keyPair);

		final DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
		accessTokenConverter.setUserTokenConverter(new SubjectAttributeUserTokenConverter(
				Stream.of(env.getActiveProfiles()).noneMatch("jpa"::equals)));
		converter.setAccessTokenConverter(accessTokenConverter);

		return converter;
	}


}