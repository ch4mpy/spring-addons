package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

public interface SessionLifecycleEventNotifier {
	void register(ReactiveSessionListener listener);
}