package com.c4_soft.springaddons.security.oauth2.test.webflux;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@AutoConfiguration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.test.web")
public class WebTestClientProperties {
	private String defaultMediaType = "application/json";
	private String defaultCharset = "utf-8";

	public String getDefaultMediaType() {
		return defaultMediaType;
	}

	public void setDefaultMediaType(String defaultMediaType) {
		this.defaultMediaType = defaultMediaType;
	}

	public String getDefaultCharset() {
		return defaultCharset;
	}

	public void setDefaultCharset(String defaultCharset) {
		this.defaultCharset = defaultCharset;
	}
}