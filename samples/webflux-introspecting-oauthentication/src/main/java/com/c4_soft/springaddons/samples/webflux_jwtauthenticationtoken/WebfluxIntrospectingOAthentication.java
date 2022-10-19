package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class WebfluxIntrospectingOAthentication {
	public static void main(String[] args) {
		new SpringApplicationBuilder(WebfluxIntrospectingOAthentication.class).web(WebApplicationType.REACTIVE).run(args);
	}
}
