package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.util.Collection;
import java.util.Optional;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionIdListener;
import jakarta.servlet.http.HttpSessionListener;
import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * A repository to store relationships between authorized clients and user sessions
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public interface AuthorizedSessionRepository extends HttpSessionListener, HttpSessionIdListener {

	public abstract HttpSession save(OAuth2AuthorizedClientId authorizedClientId, HttpSession session);

	public abstract Optional<HttpSession> delete(OAuth2AuthorizedClientId authorizedClientId);

	public abstract Optional<HttpSession> findById(OAuth2AuthorizedClientId authorizedClientId);

	public abstract Collection<OAuth2AuthorizedClientId> findAuthorizedClientIdsBySessionId(String sessionId);

	@Override
	default void sessionIdChanged(HttpSessionEvent event, String oldSessionId) {
		this.findAuthorizedClientIdsBySessionId(oldSessionId).forEach(authorizedClientId -> {
			this.delete(authorizedClientId);
			this.save(authorizedClientId, event.getSession());
		});
	}

	@Override
	default void sessionDestroyed(HttpSessionEvent se) {
		this.findAuthorizedClientIdsBySessionId(se.getSession().getId()).forEach(authorizedClientId -> {
			this.delete(authorizedClientId);
		});
	}

	// FIXME: remove once https://github.com/spring-projects/spring-security/pull/13648 is merged
	@Data
	@AllArgsConstructor
	public static class OAuth2AuthorizedClientId {
		private final String clientRegistrationId;
		private final String principalName;
	}
}