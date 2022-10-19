package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken_jpa_authorities;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class WebmvcJwtDefaultJpaAuthorities {
	public static void main(String[] args) {
		new SpringApplicationBuilder(WebmvcJwtDefaultJpaAuthorities.class).web(WebApplicationType.SERVLET).run(args);
	}
}
