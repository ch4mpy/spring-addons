package com.c4_soft.springaddons.security.oauth2.spring;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

public class GenericMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {
	private final Map<Class<? extends Authentication>, ExpressionRootSupplier<?>> methodSecurityExpressionRootSuppliers;

	public GenericMethodSecurityExpressionHandler(ExpressionRootSupplier<?>... expressionRootSuppliers) {
		this.methodSecurityExpressionRootSuppliers =
				Stream.of(expressionRootSuppliers).collect(Collectors.toMap(ExpressionRootSupplier::getAuthenticationType, ers -> ers));
	}

	@Override
	protected MethodSecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, MethodInvocation invocation) {
		final var root =
				methodSecurityExpressionRootSuppliers
						.getOrDefault(
								authentication.getClass(),
								new ExpressionRootSupplier<>(Authentication.class, () -> new GenericMethodSecurityExpressionRoot<>(Authentication.class)))
						.get();

		root.setThis(invocation.getThis());
		root.setPermissionEvaluator(getPermissionEvaluator());
		root.setTrustResolver(getTrustResolver());
		root.setRoleHierarchy(getRoleHierarchy());
		root.setDefaultRolePrefix(getDefaultRolePrefix());
		return root;
	}
}