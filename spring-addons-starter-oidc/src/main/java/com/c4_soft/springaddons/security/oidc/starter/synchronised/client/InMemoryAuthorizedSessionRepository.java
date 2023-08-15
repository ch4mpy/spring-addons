package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.http.HttpSession;

public class InMemoryAuthorizedSessionRepository implements AuthorizedSessionRepository {

	private static final Map<OAuth2AuthorizedClientId, HttpSession> index = new ConcurrentHashMap<>();

	@Override
	public HttpSession save(OAuth2AuthorizedClientId authorizedClientId, HttpSession session) {
		return index.put(authorizedClientId, session);
	}

	@Override
	public Optional<HttpSession> delete(OAuth2AuthorizedClientId authorizedClientId) {
		return Optional.ofNullable(index.remove(authorizedClientId));
	}

	@Override
	public Optional<HttpSession> findById(OAuth2AuthorizedClientId authorizedClientId) {
		return Optional.ofNullable(index.get(authorizedClientId));
	}

	@Override
	public List<OAuth2AuthorizedClientId> findAuthorizedClientIdsBySessionId(String sessionId) {
		return index.entrySet().stream().filter(e -> Objects.equals(sessionId, e.getValue().getId())).map(Map.Entry::getKey).toList();
	}
}
