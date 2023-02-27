package com.c4soft.springaddons.tutorials;

import java.net.URL;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Configuration
@ConfigurationProperties
@Data
public class ResourceServerWithUiProperties {
	/**
	 * Base URI for the OAuth2 resource-server hosting the greeting REST API
	 */
	private URL apiHost;

	/**
	 * Base URI for the OAuth2 client hosting the UI elements
	 */
	private URL uiHost;

	/**
	 * If true sessions on both this client and authorization-server are closed. If false, only this client session is terminated (user might be silently
	 * logged-in on authentication).
	 */
	private boolean rpInitiatedLogoutEnabled = true;
}
