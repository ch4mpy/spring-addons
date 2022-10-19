package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class WebfluxJwtDefault {
	public static void main(String[] args) {
		new SpringApplicationBuilder(WebfluxJwtDefault.class).web(WebApplicationType.REACTIVE).run(args);
	}
}
