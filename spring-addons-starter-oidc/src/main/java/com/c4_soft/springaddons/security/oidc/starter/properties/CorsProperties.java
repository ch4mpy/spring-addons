package com.c4_soft.springaddons.security.oidc.starter.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

@ConfigurationProperties
@Data
public class CorsProperties {
	/**
	 * Path matcher to which this configuration entry applies
	 */
	private String path = "/**";

	/**
	 * Default is null
	 */
	private Boolean allowCredentials = null;

	/**
	 * Default is "*" which allows all origins
	 */
	private String[] allowedOriginPatterns = { "*" };

	/**
	 * Default is "*" which allows all methods
	 */
	private String[] allowedMethods = { "*" };

	/**
	 * Default is "*" which allows all headers
	 */
	private String[] allowedHeaders = { "*" };

	/**
	 * Default is "*" which exposes all headers
	 */
	private String[] exposedHeaders = { "*" };

	private Long maxAge = null;
}