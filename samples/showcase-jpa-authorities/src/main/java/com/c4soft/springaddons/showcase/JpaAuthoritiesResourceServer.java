package com.c4soft.springaddons.showcase;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import com.c4soft.oauth2.rfc7519.JwtClaimSet;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetAuthentication;
import com.c4soft.springaddons.showcase.jpa.UserAuthorityRepository;

@SpringBootApplication
public class JpaAuthoritiesResourceServer {
	public static void main(String[] args) {
		SpringApplication.run(JpaAuthoritiesResourceServer.class, args);
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class SecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		private UserAuthorityRepository userRepo;

		public Converter<JwtClaimSet, Collection<GrantedAuthority>> authoritiesService() {
			return new JpaGrantedAuthoritiesConverter(userRepo);
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
					.jwt().jwtAuthenticationConverter(jwt -> new OAuth2ClaimSetAuthentication<>(
							new JwtClaimSet(jwt.getClaims()),
							authoritiesService()));
			// @formatter:on
		}
	}

	@Configuration
	@EntityScan({ "com.c4soft.springaddons.showcase.jpa" })
	@EnableJpaRepositories({ "com.c4soft.springaddons.showcase.jpa" })
	@EnableTransactionManagement
	public static class PersistenceConfig {
	}
}
