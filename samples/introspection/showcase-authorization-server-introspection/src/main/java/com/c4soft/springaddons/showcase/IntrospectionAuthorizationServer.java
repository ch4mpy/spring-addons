package com.c4soft.springaddons.showcase;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
public class IntrospectionAuthorizationServer {
	public static void main(String[] args) {
		SpringApplication.run(IntrospectionAuthorizationServer.class, args);
	}

	@EnableAuthorizationServer
	@Configuration
	public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

		AuthenticationManager authenticationManager;

		public AuthorizationServerConfiguration(AuthenticationConfiguration authenticationConfiguration) throws Exception {
			authenticationManager = authenticationConfiguration.getAuthenticationManager();
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients)
				throws Exception {
			// @formatter:off
			clients.inMemory()
				.withClient("embedded-authorities")
					.authorizedGrantTypes("password")
					.secret("{noop}secret")
					.scopes("showcase")
					.accessTokenValiditySeconds(3600)
					.autoApprove("showcase")
					.and()
				.withClient("jpa-authorities")
					.authorizedGrantTypes("password")
					.secret("{noop}secret")
					.scopes("none")
					.accessTokenValiditySeconds(3600)
					.and()
				.withClient("scope-authorites")
					.authorizedGrantTypes("password")
					.secret("{noop}secret")
					.scopes("granted-authority-scopes")
					.accessTokenValiditySeconds(3600);
			// @formatter:on
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			// @formatter:off
			endpoints
				.authenticationManager(authenticationManager)
				.tokenStore(tokenStore());
			// @formatter:on
		}

		@Bean
		public TokenStore tokenStore() {
			return new InMemoryTokenStore();
		}
	}

	/**
	 * For configuring the end users recognized by this Authorization Server
	 */
	@Configuration
	class UserConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.mvcMatchers("/.well-known/jwks.json").permitAll()
					.anyRequest().authenticated().and()
				.httpBasic().and()
				.csrf().ignoringRequestMatchers(request -> "/introspect".equals(request.getRequestURI()));
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
						.username("embedded")
						.password("password")
						.authorities("ROLE_USER", "showcase:AUTHORIZED_PERSONEL")
						.build(),
					org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder()
						.username("jpa")
						.password("password")
						.authorities("ROLE_USER")
						.build(),
					org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder()
						.username("introspection")
						.password("password")
						.authorities("ROLE_CLIENT")
						.build());
			// @formatter:on
		}
	}

}
