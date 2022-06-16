package com.c4_soft.springaddons.starter.recaptcha;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;
import reactor.netty.transport.ProxyProvider;

@Data
@Component
@ConfigurationProperties(prefix = "google.recaptcha")
public class ReCaptchaSettings {
	private String secretKey;
	private String siteverifyUrl = "https://www.google.com/recaptcha/api/siteverify";
	private double v3Threshold = .5;
	private Proxy proxy = new Proxy();

	@Data
	public class Proxy {
		private ProxyProvider.Proxy type = ProxyProvider.Proxy.HTTP;
		private String host;
		private Short port = 8080;
		private String username;
		private String password;
	}
}
