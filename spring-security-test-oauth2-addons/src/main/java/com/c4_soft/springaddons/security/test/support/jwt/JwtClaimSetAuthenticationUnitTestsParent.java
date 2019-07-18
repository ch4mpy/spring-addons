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

package com.c4_soft.springaddons.security.test.support.jwt;

import static org.mockito.Mockito.mock;

import java.util.function.Consumer;

import org.junit.runner.RunWith;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;

/**
 * @author Ch4mp
 *
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = JwtClaimSetAuthenticationUnitTestsParent.UnitTestConfig.class)
public class JwtClaimSetAuthenticationUnitTestsParent {

	public JwtClaimSetAuthenticationRequestPostProcessor securityRequestPostProcessor() {
		return new JwtClaimSetAuthenticationRequestPostProcessor();
	}

	public JwtClaimSetAuthenticationRequestPostProcessor securityRequestPostProcessor(Consumer<WithAuthoritiesJwtClaimSet.Builder<?>> claimsConsumer) {
		return new JwtClaimSetAuthenticationRequestPostProcessor(claimsConsumer);
	}

	public JwtClaimSetAuthenticationWebTestClientConfigurer securityWebTestClientConfigurer() {
		return new JwtClaimSetAuthenticationWebTestClientConfigurer();
	}

	public JwtClaimSetAuthenticationWebTestClientConfigurer securityWebTestClientConfigurer(Consumer<WithAuthoritiesJwtClaimSet.Builder<?>> claimsConsumer) {
		return new JwtClaimSetAuthenticationWebTestClientConfigurer(claimsConsumer);
	}

	@TestConfiguration
	public static class UnitTestConfig {

		@ConditionalOnMissingBean
		@Bean
		public JwtDecoder jwtDecoder() {
			return mock(JwtDecoder.class);
		}
	}

}
