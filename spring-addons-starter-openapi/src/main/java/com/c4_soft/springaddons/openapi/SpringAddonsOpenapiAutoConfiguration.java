package com.c4_soft.springaddons.openapi;

import java.util.Collection;
import org.springdoc.core.providers.ObjectMapperProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.ConversionService;

/**
 * Registers a Swagger {@code ModelConverter} which resolves enum possible values from what the
 * application actually uses to (de)serialize them (see {@link AbstractSpringEnumModelConverter}).
 * springdoc picks up any {@code ModelConverter} bean.
 */
@AutoConfiguration
public class SpringAddonsOpenapiAutoConfiguration {

  @ConditionalOnWebApplication(type = Type.SERVLET)
  @Bean
  SpringServletEnumModelConverter springServletEnumModelConverter(
      ApplicationContext applicationContext, Collection<ConversionService> conversionServices,
      ObjectMapperProvider springDocObjectMapper) {
    return new SpringServletEnumModelConverter(applicationContext, conversionServices,
        springDocObjectMapper.jsonMapper());
  }

  @ConditionalOnWebApplication(type = Type.REACTIVE)
  @Bean
  SpringReactiveEnumModelConverter springReactiveEnumModelConverter(
      ApplicationContext applicationContext, Collection<ConversionService> conversionServices,
      ObjectMapperProvider springDocObjectMapper) {
    return new SpringReactiveEnumModelConverter(applicationContext, conversionServices,
        springDocObjectMapper.jsonMapper());
  }
}
