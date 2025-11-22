package com.c4_soft.springaddons.rest.synchronised;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.client.support.RestClientHttpServiceGroupConfigurer;

/**
 * Applied only in servlet applications.
 * 
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@ConditionalOnWebApplication(type = Type.SERVLET)
@AutoConfiguration
public class SpringAddonsRestClientBeans {

  @Bean
  SpringAddonsRestClientBeanDefinitionRegistryPostProcessor springAddonsRestClientBeanDefinitionRegistryPostProcessor(
      Environment environment) {
    return new SpringAddonsRestClientBeanDefinitionRegistryPostProcessor(environment);
  }

  @Bean
  @ConditionalOnMissingBean
  RestClientHttpServiceGroupConfigurer restClientHttpServiceGroupConfigurer(RestClient biduleClient,
      RestClient machinClient) {
    return groups -> {
      groups.forEachGroup((group, clientBuilder, factoryBuilder) -> {
        if ("bidule".equals(group.name())) {
          factoryBuilder.exchangeAdapter(RestClientAdapter.create(biduleClient));
        } else if ("machin".equals(group.name())) {
          factoryBuilder.exchangeAdapter(RestClientAdapter.create(machinClient));
        }
      });
    };
  }

}
