package com.c4_soft.springaddons.starter.recaptcha;

import java.net.MalformedURLException;
import java.net.URL;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Data
@Component
@ConfigurationProperties(prefix = "google.recaptcha.key")
public class ReCaptchaSettings {
	private String site;
	private String secret;
	private URL siteverifyUrl = new URL("https://www.google.com/recaptcha/api/siteverify");
	private double v3Threshold = .5;

	public ReCaptchaSettings() throws MalformedURLException {
	}

}
