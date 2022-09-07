package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken_jpa_authorities;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ExpressionInterceptUrlRegistryPostProcessor;

@SpringBootApplication
@EnableCaching
public class SampleApi {
	public static void main(String[] args) {
		new SpringApplicationBuilder(SampleApi.class).web(WebApplicationType.SERVLET).run(args);
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class WebSecurityConfig {
		@Bean
		public ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
			return (ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry) -> registry.antMatchers("/secured-route")
					.hasRole("AUTHORIZED_PERSONNEL").anyRequest().authenticated();
		}

		@Bean
		public OAuth2AuthoritiesConverter authoritiesConverter(UserAuthorityRepository authoritiesRepo) {
			return new PersistedGrantedAuthoritiesRetriever(authoritiesRepo);
		}
	}

	@Configuration(proxyBeanMethods = false)
	@EntityScan
	@EnableJpaRepositories
	@EnableTransactionManagement
	public static class PersistenceConfig {
	}
}
