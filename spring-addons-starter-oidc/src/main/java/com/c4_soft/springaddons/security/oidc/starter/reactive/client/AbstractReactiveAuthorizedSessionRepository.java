package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientId;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * A repository to store relationships between authorized clients and user sessions
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public abstract class AbstractReactiveAuthorizedSessionRepository implements SessionListener {

	public AbstractReactiveAuthorizedSessionRepository(SessionLifecycleEventNotifier sessionEventNotifier) {
		sessionEventNotifier.register(this);
	}

	public abstract Mono<String> save(OAuth2AuthorizedClientId authorizedClientId, String sessionId);

	public abstract Mono<String> delete(OAuth2AuthorizedClientId authorizedClientId);

	public abstract Mono<String> findById(OAuth2AuthorizedClientId authorizedClientId);

	public abstract Flux<OAuth2AuthorizedClientId> findAuthorizedClientIdsBySessionId(String sessionId);

	@Override
	public void sessionRemoved(String sessionId) {
		this.findAuthorizedClientIdsBySessionId(sessionId).subscribe(authorizedClientId -> {
			this.delete(authorizedClientId).subscribe();
		});
	}
}