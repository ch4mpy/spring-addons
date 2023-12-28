package com.c4_soft.springaddons.security.oidc.spring;

import java.util.Optional;

import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * org.springframework.security.access.expression.method.MethodSecurityExpressionRoot is protected.
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 * @deprecated replaced by {@link SpringAddonsMethodSecurityExpressionRoot}
 */
@Deprecated(forRemoval = true)
public class C4MethodSecurityExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

    private Object filterObject;
    private Object returnObject;
    private Object target;

    public C4MethodSecurityExpressionRoot() {
        super(SecurityContextHolder.getContext().getAuthentication());
    }

    @SuppressWarnings("unchecked")
    protected <T extends Authentication> Optional<T> get(Class<T> expectedAuthType) {
        return Optional.ofNullable(getAuthentication()).map(a -> a.getClass().isAssignableFrom(expectedAuthType) ? (T) a : null).flatMap(Optional::ofNullable);
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
