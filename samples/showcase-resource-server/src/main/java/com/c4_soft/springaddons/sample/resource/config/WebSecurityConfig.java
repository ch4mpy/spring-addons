/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.sample.resource.config;

import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.IntrospectionClaimSetAuthenticationManager;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.JwtClaimSetAuthenticationManager;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesIntrospectionClaimSet;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableConfigurationProperties(ShowcaseResourceServerProperties.class)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	private final Environment env;

	private final JwtDecoder jwtDecoder;

	private final ShowcaseResourceServerProperties showcaseProperties;

	private final Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter;

	@Autowired
	public WebSecurityConfig(
			Environment env,
			ShowcaseResourceServerProperties showcaseProperties,
			JwtDecoder jwtDecoder,
			Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter) {
		super();
		this.env = env;
		this.showcaseProperties = showcaseProperties;
		this.jwtDecoder = jwtDecoder;
		this.authoritiesConverter = authoritiesConverter;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.sessionManagement().disable()
			.csrf()
				.ignoringAntMatchers("/actuator/**")
				.csrfTokenRepository(new CookieCsrfTokenRepository()).and()
			.requestMatcher(new AntPathRequestMatcher("/actuator/**"))
				.httpBasic().and()
				.userDetailsService(username -> {
					if(showcaseProperties.getManagement().getUsername().equals(username)) {
						return User.builder()
								.passwordEncoder(passwordEncoder()::encode)
								.username(username)
								.password(showcaseProperties.getManagement().getPassword())
								.authorities(Set.of(new SimpleGrantedAuthority("ACTUATOR")))
								.build();
					}
					throw new UsernameNotFoundException("unknown user: " + username);})
				.authorizeRequests().antMatchers("/actuator/**").hasAuthority("ACTUATOR").and()
			.requestMatcher(new AntPathRequestMatcher("/**"))
				.authorizeRequests()
					.antMatchers("/restricted/**").hasAuthority("AUTHORIZED_PERSONEL")
					.anyRequest().hasRole("USER").and();
		// @formatter:on

		configure(http.oauth2ResourceServer());
	}

	private void configure(OAuth2ResourceServerConfigurer<HttpSecurity> resourceServerHttpSecurity) {
		if (Stream.of(env.getActiveProfiles()).anyMatch("jwt"::equals)) {
			resourceServerHttpSecurity.jwt().authenticationManager(authenticationManager());
		} else {
			resourceServerHttpSecurity.opaqueToken().authenticationManager(authenticationManager());
		}
	}

	@Override
	public AuthenticationManager authenticationManager() {
		if (Stream.of(env.getActiveProfiles()).anyMatch("jwt"::equals)) {
			return new JwtClaimSetAuthenticationManager<>(
					jwtDecoder,
					WithAuthoritiesJwtClaimSet.builder("authorities")::build,
					authoritiesConverter);
		}
		return new IntrospectionClaimSetAuthenticationManager<>(
				showcaseProperties.getIntrospection().getEdpoint(),
				showcaseProperties.getIntrospection().getClientId(),
				showcaseProperties.getIntrospection().getPassword(),
				WithAuthoritiesIntrospectionClaimSet.builder("authorities")::build,
				authoritiesConverter);
	}
}