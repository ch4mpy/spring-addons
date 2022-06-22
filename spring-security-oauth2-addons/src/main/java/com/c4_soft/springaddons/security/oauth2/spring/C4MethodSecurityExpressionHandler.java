package com.c4_soft.springaddons.security.oauth2.spring;

import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class C4MethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {
	private final Supplier<C4MethodSecurityExpressionRoot> expressionRootSupplier;

	@Override
	protected MethodSecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, MethodInvocation invocation) {
		final var root = expressionRootSupplier.get();
		root.setThis(invocation.getThis());
		root.setPermissionEvaluator(getPermissionEvaluator());
		root.setTrustResolver(getTrustResolver());
		root.setRoleHierarchy(getRoleHierarchy());
		root.setDefaultRolePrefix(getDefaultRolePrefix());
		return root;
	}

}
