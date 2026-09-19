package com.c4_soft.springaddons.security.oidc.spring;

import java.util.Optional;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.jspecify.annotations.Nullable;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * org.springframework.security.access.expression.method.MethodSecurityExpressionRoot is protected.
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SpringAddonsMethodSecurityExpressionRoot extends SecurityExpressionRoot<@Nullable MethodInvocation>
		implements MethodSecurityExpressionOperations {

	private Object filterObject;
	private Object returnObject;
	private Object target;

	/**
	 * @param authentication the supplier Spring Security hands to the expression handler (respects a custom {@code SecurityContextHolderStrategy} and
	 *        keeps the evaluation lazy)
	 * @param invocation the secured method invocation
	 */
	public SpringAddonsMethodSecurityExpressionRoot(Supplier<? extends @Nullable Authentication> authentication, @Nullable MethodInvocation invocation) {
		super(authentication, invocation);
		if (invocation != null) {
			this.target = invocation.getThis();
		}
	}

	/**
	 * @deprecated the authentication is read from the static {@link SecurityContextHolder}, which ignores any custom
	 *             {@code SecurityContextHolderStrategy}. Use {@link #SpringAddonsMethodSecurityExpressionRoot(Supplier, MethodInvocation)}.
	 */
	@Deprecated
	public SpringAddonsMethodSecurityExpressionRoot() {
		this(() -> SecurityContextHolder.getContext().getAuthentication(), null);
	}

	/**
	 * @param <T> expected authentication type
	 * @param expectedAuthType expected authentication type
	 * @return the current authentication if it is an instance of the expected type (or of a sub-type), empty otherwise
	 */
	protected <T extends Authentication> Optional<T> get(Class<T> expectedAuthType) {
		return Optional.ofNullable(getAuthentication()).filter(expectedAuthType::isInstance).map(expectedAuthType::cast);
	}

	@Override
	public void setFilterObject(Object filterObject) {
		this.filterObject = filterObject;
	}

	@Override
	public Object getFilterObject() {
		return filterObject;
	}

	@Override
	public void setReturnObject(Object returnObject) {
		this.returnObject = returnObject;
	}

	@Override
	public Object getReturnObject() {
		return returnObject;
	}

	public void setThis(Object target) {
		this.target = target;
	}

	@Override
	public Object getThis() {
		return target;
	}

}
