package com.c4_soft.springaddons.security.oauth2;

public class UnparsableClaimException extends RuntimeException {
	private static final long serialVersionUID = 5585678138757632513L;

	public UnparsableClaimException(String message) {
		super(message);
	}

}
