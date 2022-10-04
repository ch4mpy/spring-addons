package com.c4_soft.springaddons.samples.webmvc_oidcauthentication;

import java.util.Collection;
import java.util.Map;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.core.GrantedAuthority;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.OAuth2AuthenticationFactory;

@SpringBootApplication
public class WebmvcJwtOauthentication {
	public static void main(String[] args) {
		new SpringApplicationBuilder(WebmvcJwtOauthentication.class).web(WebApplicationType.SERVLET).run(args);
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class SecurityConfig {
		@Bean
		OAuth2AuthenticationFactory authenticationFactory(Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
			return (bearerString, claims) -> new OAuthentication<>(new OpenidClaimSet(claims), authoritiesConverter.convert(claims), bearerString);
		}

		@Bean
		public ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
			return (ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry) -> registry.antMatchers("/secured-route")
					.hasRole("AUTHORIZED_PERSONNEL").anyRequest().authenticated();
		}
	}
}
