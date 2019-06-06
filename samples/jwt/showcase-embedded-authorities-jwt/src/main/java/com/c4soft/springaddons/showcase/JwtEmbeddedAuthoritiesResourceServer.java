package com.c4soft.springaddons.showcase;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import com.c4soft.springaddons.samples.common.ShowcaseController;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetAuthentication;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.ClaimSetGrantedAuthoritiesConverter;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;

@SpringBootApplication(scanBasePackageClasses = { ShowcaseController.class, JwtEmbeddedAuthoritiesResourceServer.class })
public class JwtEmbeddedAuthoritiesResourceServer {
	public static void main(String[] args) {
		SpringApplication.run(JwtEmbeddedAuthoritiesResourceServer.class, args);
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class SecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/restricted/**").hasAuthority("showcase:AUTHORIZED_PERSONEL")
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt()
						.jwtAuthenticationConverter(jwt -> new OAuth2ClaimSetAuthentication<>(
								new WithAuthoritiesJwtClaimSet(jwt.getClaims()),
								new ClaimSetGrantedAuthoritiesConverter<>()));
			// @formatter:on
		}
	}
}
