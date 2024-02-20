package com.c4_soft.springaddons.rest;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;

@AutoConfiguration
public class SpringAddonsRestBeans {

    @ConditionalOnMissingBean
    @Bean
    BearerProvider bearerProvider() {
        return new DefaultBearerProvider();
    }

    @ConditionalOnWebApplication(type = Type.SERVLET)
    @Bean
    SpringAddonsRestClientSupport restClientSupport(
            SpringAddonsRestProperties addonsProperties,
            BearerProvider forwardingBearerProvider,
            OAuth2AuthorizedClientManager authorizedClientManager) {
        return new SpringAddonsRestClientSupport(addonsProperties, forwardingBearerProvider, authorizedClientManager);
    }

    @Conditional(IsServletWithWebClientCondition.class)
    @Bean
    SpringAddonsWebClientSupport webClientSupport(
            SpringAddonsRestProperties addonsProperties,
            BearerProvider forwardingBearerProvider,
            OAuth2AuthorizedClientManager authorizedClientManager) {
        return new SpringAddonsWebClientSupport(addonsProperties, forwardingBearerProvider, authorizedClientManager);
    }

    @ConditionalOnWebApplication(type = Type.REACTIVE)
    @Bean
    ReactiveSpringAddonsWebClientSupport reactiveWebClientSupport(
            SpringAddonsRestProperties addonsProperties,
            BearerProvider forwardingBearerProvider,
            ReactiveOAuth2AuthorizedClientManager authorizedClientManager) {
        return new ReactiveSpringAddonsWebClientSupport(addonsProperties, forwardingBearerProvider, authorizedClientManager);
    }
}
