package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientId;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public class InMemoryReactiveAuthorizedSessionRepository extends AbstractReactiveAuthorizedSessionRepository {
	public InMemoryReactiveAuthorizedSessionRepository(SessionLifecycleEventNotifier sessionEventNotifier) {
		super(sessionEventNotifier);
	}

	private static final Map<OAuth2AuthorizedClientId, String> index = new ConcurrentHashMap<>();

	@Override
	public Mono<String> save(OAuth2AuthorizedClientId authorizedClientId, String sessionId) {
		return Mono.justOrEmpty(index.put(authorizedClientId, sessionId));
	}

	@Override
	public Mono<String> delete(OAuth2AuthorizedClientId authorizedClientId) {
		return Mono.justOrEmpty(index.remove(authorizedClientId));
	}

	@Override
	public Mono<String> findById(OAuth2AuthorizedClientId authorizedClientId) {
		return Mono.justOrEmpty(index.get(authorizedClientId));
	}

	@Override
	public Flux<OAuth2AuthorizedClientId> findAuthorizedClientIdsBySessionId(String sessionId) {
		return Flux.fromStream(index.entrySet().stream()).filter(e -> Objects.equals(sessionId, e.getValue())).map(Map.Entry::getKey);
	}
}
