/*
 * Copyright 2019 Jérôme Wacongne.
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
package org.springframework.security.test.context.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.test.configuration.JwtTestConfiguration;
import org.springframework.stereotype.Component;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = MessageServiceTests.SecurityConfiguration.class)
public class MessageServiceTests {

	@Autowired
	private MessageService messageService;

	@Test(expected = AuthenticationCredentialsNotFoundException.class)
	public void greetWitoutMockJwt() {
		messageService.getGreeting();
	}

	@Test
	@WithMockJwt(@StringAttribute(name = JwtClaimNames.SUB, value = "ch4mpy"))
	public void greetWithMockJwt() {
		assertThat(messageService.getGreeting()).isEqualTo("Hello, ch4mpy!");
	}

	@Test(expected = AccessDeniedException.class)
	@WithMockJwt
	public void secretWithoutMessageReadScope() {
		assertThat(messageService.getSecret()).isEqualTo("Secret message");
	}

	@Test
	@WithMockJwt(@StringAttribute(name = "scope", value = "message:read"))
	public void secretWithScopeMessageReadAuthority() {
		assertThat(messageService.getSecret()).isEqualTo("Secret message");
	}

	interface MessageService {

		@PreAuthorize("authenticated")
		String getGreeting();

		@PreAuthorize("hasAuthority('message:read')")
		String getSecret();
	}

	@Component
	static final class MessageServiceImpl implements MessageService {

		@Override
		public String getGreeting() {
			return String.format("Hello, %s!", SecurityContextHolder.getContext().getAuthentication().getName());
		}

		@Override
		public String getSecret() {
			return "Secret message";
		}

	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@ComponentScan(basePackageClasses = MessageService.class)
	@Import(JwtTestConfiguration.class)
	static class SecurityConfiguration {
		@Bean
		Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter() {
			return jwt -> Stream.of(jwt.containsClaim("scope") ? jwt.getClaimAsString("scope").split(" ") : new String[] {})
					.map(SimpleGrantedAuthority::new)
					.collect(Collectors.toSet());
		}
	}
}
