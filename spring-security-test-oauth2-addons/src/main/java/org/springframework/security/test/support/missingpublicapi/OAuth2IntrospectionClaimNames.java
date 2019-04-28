package org.springframework.security.test.support.missingpublicapi;

public interface OAuth2IntrospectionClaimNames {

	/**
	 * {@code active} - Indicator whether or not the token is currently active
	 */
	String ACTIVE = "active";

	/**
	 * {@code scope} - The scopes for the token
	 */
	String SCOPE = "scope";

	/**
	 * {@code client_id} - The Client identifier for the token
	 */
	String CLIENT_ID = "client_id";

	/**
	 * {@code username} - A human-readable identifier for the resource owner that authorized the token
	 */
	String USERNAME = "username";

	/**
	 * {@code token_type} - The type of the token, for example {@code bearer}.
	 */
	String TOKEN_TYPE = "token_type";

	/**
	 * {@code exp} - A timestamp indicating when the token expires
	 */
	String EXPIRES_AT = "exp";

	/**
	 * {@code iat} - A timestamp indicating when the token was issued
	 */
	String ISSUED_AT = "iat";

	/**
	 * {@code nbf} - A timestamp indicating when the token is not to be used before
	 */
	String NOT_BEFORE = "nbf";

	/**
	 * {@code sub} - Usually a machine-readable identifier of the resource owner who authorized the token
	 */
	String SUBJECT = "sub";

	/**
	 * {@code aud} - The intended audience for the token
	 */
	String AUDIENCE = "aud";

	/**
	 * {@code iss} - The issuer of the token
	 */
	String ISSUER = "iss";

	/**
	 * {@code jti} - The identifier for the token
	 */
	String JTI = "jti";
}