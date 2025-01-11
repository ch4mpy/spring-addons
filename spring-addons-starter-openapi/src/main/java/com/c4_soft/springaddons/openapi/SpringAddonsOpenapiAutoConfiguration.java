package com.c4_soft.springaddons.openapi;

import java.io.IOException;
import java.util.Collection;
import org.springdoc.core.providers.ObjectMapperProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.format.support.FormattingConversionService;
import org.springframework.http.converter.HttpMessageNotWritableException;

@AutoConfiguration
public class SpringAddonsOpenapiAutoConfiguration {

  @ConditionalOnWebApplication(type = Type.SERVLET)
  @Bean
  SpringServletEnumModelConverter springServletEnumModelConverter(
      ApplicationContext applicationContext,
      Collection<FormattingConversionService> formattingConversionService,
      ObjectMapperProvider springDocObjectMapper)
      throws HttpMessageNotWritableException, IOException {
    return new SpringServletEnumModelConverter(applicationContext, formattingConversionService,
        springDocObjectMapper);
  }

  @ConditionalOnWebApplication(type = Type.REACTIVE)
  // @Bean
  SpringReactiveEnumModelConverter springReactiveEnumModelConverter(
      ApplicationContext applicationContext,
      FormattingConversionService formattingConversionService,
      ObjectMapperProvider springDocObjectMapper)
      throws HttpMessageNotWritableException, IOException {
    return new SpringReactiveEnumModelConverter(applicationContext, formattingConversionService,
        springDocObjectMapper);
  }
}
