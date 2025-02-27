package com.c4_soft.springaddons.rest.reactive;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.web.server.ServerWebExchange;

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

  @Bean
  @Conditional(DefaultReactiveAuthorizationFailureHandlerCondition.class)
  ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler(
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
    return new RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler(
        (clientRegistrationId, principal, attributes) -> authorizedClientRepository
            .removeAuthorizedClient(clientRegistrationId, principal,
                (ServerWebExchange) attributes.get(ServerWebExchange.class.getName())));
  }
}
