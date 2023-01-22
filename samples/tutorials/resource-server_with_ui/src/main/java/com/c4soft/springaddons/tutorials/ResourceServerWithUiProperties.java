package com.c4soft.springaddons.tutorials;

import java.net.URL;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Configuration
@ConfigurationProperties
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResourceServerWithUiProperties {
	private URL apiHost;
}
