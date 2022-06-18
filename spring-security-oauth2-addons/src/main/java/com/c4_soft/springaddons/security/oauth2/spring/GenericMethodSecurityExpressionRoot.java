package com.c4_soft.springaddons.security.oauth2.spring;

import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

/**
 * <p>
 * org.springframework.security.access.expression.method.MethodSecurityExpressionRoot is protected.
 * </p>
 *
 * @author     ch4mp
 * @param  <T> type of Authentication in the security-context
 */
public class GenericMethodSecurityExpressionRoot<T extends Authentication> extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

	private Object filterObject;
	private Object returnObject;
	private Object target;
	private final Class<T> authenticationType;

	public GenericMethodSecurityExpressionRoot(Class<T> authenticationType) {
		super(SecurityContextHolder.getContext().getAuthentication());
		Assert.isAssignable(authenticationType, getAuthentication().getClass());
		this.authenticationType = authenticationType;
	}

	@SuppressWarnings("unchecked")
	public T getAuth() {
		return (T) getAuthentication();
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

	public Class<T> getAuthenticationType() {
		return authenticationType;
	}

}
