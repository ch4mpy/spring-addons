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

package com.c4_soft.springaddons.test.security.web.servlet.request;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.c4_soft.oauth2.UnmodifiableClaimSet;
import com.c4_soft.springaddons.test.security.support.ClaimSetAuthenticationTestingBuilder;
import com.c4_soft.springaddons.test.security.support.Defaults;

/**
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 */
@Import(ServletClaimSetAuthenticationUnitTestingSupport.UnitTestConfig.class)
public abstract class ServletClaimSetAuthenticationUnitTestingSupport<T extends UnmodifiableClaimSet & Principal, U extends ClaimSetAuthenticationTestingBuilder<T, U>>
		extends
		ServletUnitTestingSupport {

	/**
	 * @return a pre-configured {@link RequestPostProcessor} inject a mocked
	 * {@code OAuth2ClaimSetAuthentication<JwtClaimSet>} in test security context
	 */
	public abstract U authentication();

	/**
	 * @param claimsConsumer {@link Consumer} to configure JWT claim-set
	 * @return a pre-configured {@link RequestPostProcessor} inject a mocked
	 * {@code OAuth2ClaimSetAuthentication<JwtClaimSet>} in test security context
	 */
	public U authentication(Consumer<Map<String, Object>> claimsConsumer) {
		final var requestPostProcessor = authentication();
		requestPostProcessor.claims(claimsConsumer);
		return requestPostProcessor;
	}

	@TestConfiguration
	public static class UnitTestConfig<T extends UnmodifiableClaimSet & Principal> {

		@ConditionalOnMissingBean
		@Bean
		@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
		public Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter() {
			final var mockAuthoritiesConverter = mock(ClaimSet2AuthoritiesConverter.class);

			when(mockAuthoritiesConverter.convert(any())).thenReturn(Defaults.GRANTED_AUTHORITIES);

			return mockAuthoritiesConverter;
		}

		private interface ClaimSet2AuthoritiesConverter extends Converter<Map<String, Object>, Set<GrantedAuthority>> {
		}
	}

}
