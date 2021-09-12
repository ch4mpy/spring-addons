/*
 * Copyright 2020 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.service.JwtAuthenticationTokenMessageService;
import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.web.GreetingController;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;

/**
 * Spring-boot application retrieving user ID from the JWT delivered by a Keycloak authorization-server and authorities defined from a
 * database
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@SpringBootApplication(scanBasePackageClasses = { JwtAuthenticationTokenMessageService.class, GreetingController.class })
public class JwtAuthenticationTokenServletAppWithJwtEmbeddedAuthorities {
	@Configuration
	public static class JwtConfig {
		static class JwtToJwtAuthenticationTokenConverterImpl implements Converter<Jwt, JwtAuthenticationToken> {
			private final Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

			public JwtToJwtAuthenticationTokenConverterImpl(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
				this.authoritiesConverter = authoritiesConverter;
			}

			@Override
			public JwtAuthenticationToken convert(Jwt jwt) {
				return new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt));
			}

		}

		@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
		String issuerUri;

		@Bean
		public Converter<Jwt, JwtAuthenticationToken> authenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			return new JwtToJwtAuthenticationTokenConverterImpl(authoritiesConverter);
		}

		@Bean
		public Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter() {
			return (Jwt jwt) -> {
				final JSONObject realmAccess = (JSONObject) jwt.getClaims().get("realm_access");
				final JSONArray roles = (JSONArray) realmAccess.get("roles");
				return roles.stream().map(Object::toString).map(role -> new SimpleGrantedAuthority("ROLE_" + role)).collect(Collectors.toSet());
			};
		}

		@Bean
		public JwtDecoder jwtDecoder() {
			return JwtDecoders.fromOidcIssuerLocation(issuerUri);
		}
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		Converter<Jwt, JwtAuthenticationToken> authenticationConverter;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http.csrf().disable().httpBasic().disable().formLogin().disable();
			http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter);
			http.authorizeRequests().antMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL").anyRequest()
					.authenticated();
			// @formatter:on
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(JwtAuthenticationTokenServletAppWithJwtEmbeddedAuthorities.class, args);
	}
}
