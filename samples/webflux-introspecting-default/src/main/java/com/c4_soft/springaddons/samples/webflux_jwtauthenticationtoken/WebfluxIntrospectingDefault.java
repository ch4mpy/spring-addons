package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class WebfluxIntrospectingDefault {
	public static void main(String[] args) {
		new SpringApplicationBuilder(WebfluxIntrospectingDefault.class).web(WebApplicationType.REACTIVE).run(args);
	}
}
