package com.c4_soft.springaddons.rest.reactive;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Applied only in reactive (WebFlux) applications.
 * 
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@ConditionalOnWebApplication(type = Type.REACTIVE)
@AutoConfiguration
public class SpringAddonsServerWebClientBeans {

  @Bean
  SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessor springAddonsWebClientBeanDefinitionRegistryPostProcessor(
      Environment environment) {
    return new SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessor(environment);
  }
}
