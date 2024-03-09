package com.c4_soft.springaddons.openapi;

import java.io.IOException;

import org.springdoc.core.providers.ObjectMapperProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.converter.HttpMessageNotWritableException;

@AutoConfiguration
public class SpringAddonsOpenapiAutoConfiguration {

	@ConditionalOnWebApplication(type = Type.SERVLET)
	@Bean
	SpringServletEnumModelConverter springServletEnumModelConverter(ApplicationContext applicationContext, ObjectMapperProvider springDocObjectMapper)
			throws HttpMessageNotWritableException,
			IOException {
		return new SpringServletEnumModelConverter(applicationContext, springDocObjectMapper);
	}
}
