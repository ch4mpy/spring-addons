package com.c4_soft.springaddons.security.oauth2.test.annotations;

public class InvalidClaimException extends RuntimeException {
	private static final long serialVersionUID = -2603521800687945747L;

	public InvalidClaimException(Throwable t) {
		super(t);
	}

}
