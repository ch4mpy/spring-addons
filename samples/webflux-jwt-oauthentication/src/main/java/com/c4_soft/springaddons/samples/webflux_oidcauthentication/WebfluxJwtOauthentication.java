package com.c4_soft.springaddons.samples.webflux_oidcauthentication;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class WebfluxJwtOauthentication {
	public static void main(String[] args) {
		new SpringApplicationBuilder(WebfluxJwtOauthentication.class).web(WebApplicationType.REACTIVE).run(args);
	}
}
