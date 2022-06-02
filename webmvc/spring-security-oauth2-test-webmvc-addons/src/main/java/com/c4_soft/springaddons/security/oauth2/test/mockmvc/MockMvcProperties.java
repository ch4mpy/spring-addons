package com.c4_soft.springaddons.security.oauth2.test.mockmvc;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

@Data
@AutoConfiguration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.test.web")
public class MockMvcProperties {
	private String defaultMediaType = "application/json";
	private String defaultCharset = "utf-8";
}