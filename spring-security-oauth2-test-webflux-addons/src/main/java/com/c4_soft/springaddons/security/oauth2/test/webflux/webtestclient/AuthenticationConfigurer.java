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
package com.c4_soft.springaddons.security.oauth2.test.webflux.webtestclient;

import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.reactive.server.MockServerConfigurer;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

import com.c4_soft.springaddons.security.oauth2.AuthenticationBuilder;

/**
 * Redundant code for {@link Authentication} WebTestClient configurers
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 * @param <T> concrete {@link Authentication} type to build and configure in test security context
 */
public interface AuthenticationConfigurer<T extends Authentication> extends WebTestClientConfigurer, MockServerConfigurer, AuthenticationBuilder<T> {
	@Override
	default void beforeServerCreated(final WebHttpHandlerBuilder builder) {
		configurer().beforeServerCreated(builder);
	}

	@Override
	default void afterConfigureAdded(final WebTestClient.MockServerSpec<?> serverSpec) {
		configurer().afterConfigureAdded(serverSpec);
	}

	@Override
	default void afterConfigurerAdded(
			WebTestClient.Builder builder,
			@Nullable WebHttpHandlerBuilder httpHandlerBuilder,
			@Nullable ClientHttpConnector connector) {
		configurer().afterConfigurerAdded(builder, httpHandlerBuilder, connector);
	}

	private <U extends WebTestClientConfigurer & MockServerConfigurer> U configurer() {
		return org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication(build());
	}
}
