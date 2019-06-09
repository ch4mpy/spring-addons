package com.c4soft.springaddons.showcase;

import java.security.KeyPair;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
public class AuthorizationServer {
	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServer.class, args);
	}

	@EnableAuthorizationServer
	@Configuration
	public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

		AuthenticationManager authenticationManager;
		KeyPair keyPair;
		boolean jwtEnabled;

		@Autowired
		public AuthorizationServerConfiguration(
				AuthenticationConfiguration authenticationConfiguration,
				@Value("${jwt.enabled}") boolean jwtEnabled,
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
		@ConditionalOnProperty("jwt.enabled")
		public JwtAccessTokenConverter accessTokenConverter() {
			final var converter = new JwtAccessTokenConverter();
			converter.setKeyPair(keyPair);

			final DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
			accessTokenConverter.setUserTokenConverter(new SubjectAttributeUserTokenConverter());
			converter.setAccessTokenConverter(accessTokenConverter);

			return converter;
		}


	}

	@Configuration
	public class ExtraEndpointsSecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		ClientDetailsService clientDetailsService;

		@Override
		public void configure(HttpSecurity security) throws Exception {
			// @formatter:off
			security
				.userDetailsService(new ClientDetailsUserDetailsService(clientDetailsService))
				.requestMatchers()
					.mvcMatchers("/.well-known/jwks.json", "/introspect").and()
				.authorizeRequests()
					.mvcMatchers("/.well-known/jwks.json").permitAll()
					.mvcMatchers("/introspect").hasAuthority("INTROSPECTION_CLIENT")
					.anyRequest().authenticated().and()
				.httpBasic().and()
				.csrf().ignoringRequestMatchers(request -> "/introspect".equals(request.getRequestURI()));
			// @formatter:on

		}

		@Bean
		@Override
		public UserDetailsService userDetailsService() {
			//@formatter:off
			return new InMemoryUserDetailsManager(
					org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder()
						.username("user")
						.password("password")
						.authorities("ROLE_USER")
						.build(),
					org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder()
						.username("admin")
						.password("password")
						.authorities("ROLE_USER", "showcase:AUTHORIZED_PERSONEL")
						.build(),
					org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder()
						.username("jpa")
						.password("password")
						.authorities(Collections.emptySet())
						.build());
			// @formatter:on
		}

	}
}
