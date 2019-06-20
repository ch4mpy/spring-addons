/*
 * Copyright 2019 Jérôme Wacongne
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
package com.c4soft.springaddons.sample.resource.config;

import java.util.Set;

import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@Order(99)
public class ActuatorSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	public void configure(HttpSecurity security) throws Exception {
		// @formatter:off
		security
			.requestMatcher(EndpointRequest.toAnyEndpoint())
			.userDetailsService(new InMemoryUserDetailsManager(
				org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder()
					.username("actuator")
					.password("secret")
					.authorities(Set.of(new SimpleGrantedAuthority("ACTUATOR")))
					.build()))
			.authorizeRequests().anyRequest().hasAuthority("ACTUATOR").and()
			.httpBasic().and()
			.csrf().ignoringAntMatchers("/actuator/**");
		// @formatter:on
	}

}