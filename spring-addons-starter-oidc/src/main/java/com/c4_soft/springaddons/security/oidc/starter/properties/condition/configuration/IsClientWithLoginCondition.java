package com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration;

import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.StringUtils;

/**
 * Matches when {@code com.c4-soft.springaddons.oidc.client.security-matchers} has at least one
 * non-blank entry, whether it is set as a comma separated list or as indexed properties.
 */
public class IsClientWithLoginCondition implements Condition {
	static final String SECURITY_MATCHERS_PROPERTY = "com.c4-soft.springaddons.oidc.client.security-matchers";

	@Override
	public boolean matches(@NonNull ConditionContext context, @NonNull AnnotatedTypeMetadata metadata) {
		return hasSecurityMatchers(context.getEnvironment());
	}

	public static boolean hasSecurityMatchers(Environment environment) {
		return Binder
				.get(environment)
				.bind(SECURITY_MATCHERS_PROPERTY, Bindable.listOf(String.class))
				.orElseGet(List::of)
				.stream()
				.anyMatch(StringUtils::hasText);
	}

}
