package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import org.springframework.session.Session;

public interface SessionListener {
	default void sessionCreated(Session session) {
	}

	default void sessionRemoved(String sessionId) {
	}
}