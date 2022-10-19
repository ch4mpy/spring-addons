package com.c4_soft.springaddons.samples.webmvc_oidcauthentication;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class WebmvcJwtOauthentication {
	public static void main(String[] args) {
		new SpringApplicationBuilder(WebmvcJwtOauthentication.class).web(WebApplicationType.SERVLET).run(args);
	}
}
