package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import org.springframework.web.server.WebSession;

public interface ReactiveSessionListener {
	default void sessionCreated(WebSession session) {
	}

	default void sessionRemoved(String sessionId) {
	}
}