package com.c4_soft.springaddons.rest.synchronised;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.env.Environment;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Applied only in servlet applications and only if {@link WebClient} is on the classpath.
 * 
 * @author ch4mp&#64;c4-soft.com
 */
@Conditional(IsServletWithWebClientCondition.class)
@AutoConfiguration
public class SpringAddonsServletWebClientBeans {

  @Bean
  SpringAddonsServletWebClientBeanDefinitionRegistryPostProcessor springAddonsWebClientBeanDefinitionRegistryPostProcessor(
      Environment environment) {
    return new SpringAddonsServletWebClientBeanDefinitionRegistryPostProcessor(environment);
  }
}
