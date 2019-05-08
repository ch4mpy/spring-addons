package org.springframework.security.test.web.reactive.server;

import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.support.AuthenticationBuilder;
import org.springframework.test.web.reactive.server.MockServerConfigurer;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

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
