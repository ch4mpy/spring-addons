package com.c4_soft.springaddons.security.oauth2.test.mockmvc;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.test.web")
public class MockMvcProperties {
	private String defaultMediaType = "application/json";
	private String defaultCharset = "utf-8";
}