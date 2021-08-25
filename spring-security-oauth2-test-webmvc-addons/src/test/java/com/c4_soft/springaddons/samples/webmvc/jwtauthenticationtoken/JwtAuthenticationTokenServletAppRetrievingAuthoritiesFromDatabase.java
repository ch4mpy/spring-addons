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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
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
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.jpa.PersistedGrantedAuthoritiesRetriever;
import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.jpa.UserAuthority;
import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.jpa.UserAuthorityRepository;
import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.service.JwtAuthenticationTokenMessageService;
import com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.web.GreetingController;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@SpringBootApplication(scanBasePackageClasses = { JwtAuthenticationTokenMessageService.class, GreetingController.class })
public class JwtAuthenticationTokenServletAppRetrievingAuthoritiesFromDatabase {
	public static void main(String[] args) {
		SpringApplication.run(JwtAuthenticationTokenServletAppRetrievingAuthoritiesFromDatabase.class, args);
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		UserAuthorityRepository authoritiesRepo;

		public Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter(UserAuthorityRepository authoritiesRepo) {
			return new PersistedGrantedAuthoritiesRetriever(authoritiesRepo);
		}

		public Converter<Jwt, JwtAuthenticationToken> authenticationConverter(UserAuthorityRepository authoritiesRepo) {
			return new JwtToJwtAuthenticationTokenConverterImpl(authoritiesConverter(authoritiesRepo));
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http.csrf().disable().httpBasic().disable().formLogin().disable();
			http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter(authoritiesRepo));
			http.authorizeRequests().antMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL").anyRequest()
					.authenticated();
			// @formatter:on
		}

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
	}

	@Configuration(proxyBeanMethods = false)
	public static class JwtConfig {
		@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
		String issuerUri;

		@Bean
		public JwtDecoder jwtDecoder() {
			return JwtDecoders.fromOidcIssuerLocation(issuerUri);
		}
	}

	@Configuration(proxyBeanMethods = false)
	@EntityScan(basePackageClasses = UserAuthority.class)
	public static class PersistenceConfig {
	}
}
