package com.c4_soft.springaddons.security.oauth2.spring;

import java.util.function.Supplier;

import org.springframework.security.core.Authentication;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class ExpressionRootSupplier<T extends Authentication> implements Supplier<GenericMethodSecurityExpressionRoot<T>> {

	private final Class<T> authenticationType;
	private final Supplier<GenericMethodSecurityExpressionRoot<T>> delegate;

	@Override
	public GenericMethodSecurityExpressionRoot<T> get() {
		return delegate.get();
	}

}
