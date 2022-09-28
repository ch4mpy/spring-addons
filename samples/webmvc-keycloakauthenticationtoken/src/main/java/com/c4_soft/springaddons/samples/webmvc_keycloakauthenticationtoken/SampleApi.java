package com.c4_soft.springaddons.samples.webmvc_keycloakauthenticationtoken;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

/**
 * Keycloak adapters for spring are deprecated. Refer to other sample for alternatives.
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@SpringBootApplication
@EnableMethodSecurity(prePostEnabled = true)
public class SampleApi {
	public static void main(String[] args) {
		new SpringApplicationBuilder(SampleApi.class).web(WebApplicationType.SERVLET).run(args);
	}

	@Bean
	public KeycloakConfigResolver keycloakConfigResolver() {
		return new KeycloakSpringBootConfigResolver();
	}

	@Configuration
	@EnableWebSecurity
	@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
	public static class WebSecurityConf extends KeycloakWebSecurityConfigurerAdapter {

		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
			keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new NullAuthoritiesMapper());
			auth.authenticationProvider(keycloakAuthenticationProvider);
		}

		@Bean
		@Override
		protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
			return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);
			http.authorizeRequests().antMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL").anyRequest().authenticated();
			http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			http.csrf().disable();
		}

	}
}
