package com.c4soft.springaddons.showcase;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetIntrospectionAuthenticationManager;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.ClaimSetGrantedAuthoritiesConverter;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesIntrospectionClaimSet;

@SpringBootApplication
@ComponentScan("com.c4soft.springaddons.samples.common")
public class IntrospectionEmbeddedAuthoritiesResourceServer {
	public static void main(String[] args) {
		SpringApplication.run(IntrospectionEmbeddedAuthoritiesResourceServer.class, args);
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class AlternanteSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/restricted/**").hasAuthority("showcase:AUTHORIZED_PERSONEL")
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.opaqueToken()
						.authenticationManager(authenticationManager());
			// @formatter:on
		}

		@Override
		public OAuth2ClaimSetIntrospectionAuthenticationManager<WithAuthoritiesIntrospectionClaimSet> authenticationManager() {
			return new OAuth2ClaimSetIntrospectionAuthenticationManager<WithAuthoritiesIntrospectionClaimSet>(
					"https://localhost:9080/introspect",
					"introspection",
					"password",
					WithAuthoritiesIntrospectionClaimSet::new,
					new ClaimSetGrantedAuthoritiesConverter<>());
		}
	}
}
