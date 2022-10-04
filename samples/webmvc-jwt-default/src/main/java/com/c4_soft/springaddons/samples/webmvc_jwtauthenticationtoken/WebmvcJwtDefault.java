package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;

import com.c4_soft.springaddons.security.oauth2.config.synchronised.ExpressionInterceptUrlRegistryPostProcessor;

@SpringBootApplication
public class WebmvcJwtDefault {
	public static void main(String[] args) {
		new SpringApplicationBuilder(WebmvcJwtDefault.class).web(WebApplicationType.SERVLET).run(args);
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class SecurityConfig {
		@Bean
		ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
			return (ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry) -> registry.antMatchers("/secured-route")
					.hasRole("AUTHORIZED_PERSONNEL").anyRequest().authenticated();
		}
	}
}
