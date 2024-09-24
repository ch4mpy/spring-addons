package com.c4_soft.springaddons.starter.recaptcha;

import java.net.URL;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Data
@Component
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.recaptcha")
public class C4ReCaptchaSettings {
	private String secretKey;
	@Value("${siteverify-url:https://www.google.com/recaptcha/api/siteverify}")
	private URL siteverifyUrl;
	private double v3Threshold = .5;
}
