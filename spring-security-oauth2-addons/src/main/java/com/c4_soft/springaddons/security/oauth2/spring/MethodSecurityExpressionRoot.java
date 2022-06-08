package com.c4_soft.springaddons.security.oauth2.spring;

import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

public class MethodSecurityExpressionRoot<T extends Authentication> extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

	private Object filterObject;
	private Object returnObject;
	private Object target;

	public MethodSecurityExpressionRoot(Class<T> authenticationType) {
		super(SecurityContextHolder.getContext().getAuthentication());
		Assert.isAssignable(authenticationType, getAuthentication().getClass());
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

}
