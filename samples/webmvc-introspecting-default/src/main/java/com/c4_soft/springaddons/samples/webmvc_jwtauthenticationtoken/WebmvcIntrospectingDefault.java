package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class WebmvcIntrospectingDefault {
	public static void main(String[] args) {
		new SpringApplicationBuilder(WebmvcIntrospectingDefault.class).web(WebApplicationType.SERVLET).run(args);
	}
}
