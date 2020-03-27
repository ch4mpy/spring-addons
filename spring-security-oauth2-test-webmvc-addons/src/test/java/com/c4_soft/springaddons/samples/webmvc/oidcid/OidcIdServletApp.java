/*
 * Copyright 2020 Jérôme Wacongne
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
package com.c4_soft.springaddons.samples.webmvc.oidcid;

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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.stereotype.Service;

import com.c4_soft.springaddons.samples.webmvc.common.domain.MessageService;
import com.c4_soft.springaddons.samples.webmvc.common.web.GreetingController;
import com.c4_soft.springaddons.samples.webmvc.oidcid.OidcIdServletApp.OidcIdMessageService;
import com.c4_soft.springaddons.security.oauth2.keycloak.KeycloackEmbeddedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.keycloak.KeycloackOidcIdAuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdAuthenticationToken;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@SpringBootApplication(scanBasePackageClasses = { OidcIdMessageService.class, GreetingController.class })
public class OidcIdServletApp {
	public static void main(String[] args) {
		SpringApplication.run(OidcIdServletApp.class, args);
	}

	@Service
	public static class OidcIdMessageService implements MessageService<OidcIdAuthenticationToken> {

		@Override
		public String getSecret() {
			return "Secret message";
		}

		@Override
		public String greet(OidcIdAuthenticationToken who) {
			return String.format(
					"Hello %s! You are granted with %s.",
					who.getPrincipal().getPreferredUsername(),
					who.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
		}

	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		Converter<Jwt, OidcIdAuthenticationToken> authenticationConverter;

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

	@Configuration
	public static class JwtConfig {
		@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
		String issuerUri;

		@Bean
		public JwtDecoder jwtDecoder() {
			return JwtDecoders.fromOidcIssuerLocation(issuerUri);
		}

		@Bean
		public Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter() {
			return new KeycloackEmbeddedAuthoritiesConverter();
		}

		@Bean
		public Converter<Jwt, OidcIdAuthenticationToken>
				authenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			return new KeycloackOidcIdAuthenticationConverter(authoritiesConverter);
		}
	}
}
