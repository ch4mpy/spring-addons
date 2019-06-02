
package com.c4soft.springaddons.showcase;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import com.c4soft.oauth2.rfc7662.IntrospectionClaimSet;
import com.c4soft.springaddons.samples.common.jpa.JpaGrantedAuthoritiesConverter;
import com.c4soft.springaddons.samples.common.jpa.UserAuthorityRepository;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetIntrospectionAuthenticationManager;

@SpringBootApplication
@ComponentScan("com.c4soft.springaddons.samples.common")
public class IntrospectionJpaAuthoritiesResourceServer {
	public static void main(String[] args) {
		SpringApplication.run(IntrospectionJpaAuthoritiesResourceServer.class, args);
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class SecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		private UserAuthorityRepository userRepo;

		public Converter<IntrospectionClaimSet, Collection<GrantedAuthority>> authoritiesService() {
			return new JpaGrantedAuthoritiesConverter<>(userRepo);
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/restricted/**").hasAuthority("AUTHORIZED_PERSONEL")
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
				.opaqueToken()
				.authenticationManager(authenticationManager());
			// @formatter:on
		}

		@Override
		public OAuth2ClaimSetIntrospectionAuthenticationManager<IntrospectionClaimSet> authenticationManager() {
			return new OAuth2ClaimSetIntrospectionAuthenticationManager<IntrospectionClaimSet>(
					"https://localhost:9080/introspect",
					"introspection",
					"password",
					IntrospectionClaimSet::new,
					authoritiesService());
		}
	}

	@Configuration
	@EntityScan({ "com.c4soft.springaddons.samples.common.jpa" })
	@EnableJpaRepositories({ "com.c4soft.springaddons.samples.common.jpa" })
	@EnableTransactionManagement
	public static class PersistenceConfig {
	}
}
