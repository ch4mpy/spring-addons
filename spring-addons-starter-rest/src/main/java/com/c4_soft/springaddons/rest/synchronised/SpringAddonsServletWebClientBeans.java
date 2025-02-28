package com.c4_soft.springaddons.rest.synchronised;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.RemoveAuthorizedClientOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.WebClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Applied only in servlet applications and only if {@link WebClient} is on the classpath.
 * 
 * @author ch4mp&#64;c4-soft.com
 */
@Conditional(IsServletWithWebClientCondition.class)
@AutoConfiguration
public class SpringAddonsServletWebClientBeans {

  private static final String HTTP_SERVLET_REQUEST_ATTR_NAME = HttpServletRequest.class.getName();

  private static final String HTTP_SERVLET_RESPONSE_ATTR_NAME = HttpServletResponse.class.getName();

  @Bean
  SpringAddonsServletWebClientBeanDefinitionRegistryPostProcessor springAddonsWebClientBeanDefinitionRegistryPostProcessor(
      Environment environment) {
    return new SpringAddonsServletWebClientBeanDefinitionRegistryPostProcessor(environment);
  }

  @Bean
  @Conditional(DefaultAuthorizationFailureHandlerCondition.class)
  OAuth2AuthorizationFailureHandler authorizationFailureHandler(
      OAuth2AuthorizedClientRepository authorizedClientRepository) {
    return new RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(
        (clientRegistrationId, principal, attributes) -> {
          authorizedClientRepository.removeAuthorizedClient(clientRegistrationId, principal,
              (HttpServletRequest) attributes.get(HTTP_SERVLET_REQUEST_ATTR_NAME),
              (HttpServletResponse) attributes.get(HTTP_SERVLET_RESPONSE_ATTR_NAME));
        });
  }
}
