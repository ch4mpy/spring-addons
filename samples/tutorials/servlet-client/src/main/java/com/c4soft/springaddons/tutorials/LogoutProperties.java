package com.c4soft.springaddons.tutorials;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix = "logout")
public class LogoutProperties {
	private Map<String, LogoutProperties.ProviderLogoutProperties> registration = new HashMap<>();

	@Data
	static class ProviderLogoutProperties {
		private URI logoutUri;
		private String postLogoutUriParameterName;
	}
}