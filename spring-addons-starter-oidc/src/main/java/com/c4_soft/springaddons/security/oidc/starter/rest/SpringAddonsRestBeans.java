package com.c4_soft.springaddons.security.oidc.starter.rest;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.HasRestConfiguration;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.IsServletWithWebClientCondition;

@Conditional(HasRestConfiguration.class)
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
            SpringAddonsOidcProperties addonsProperties,
            OAuth2AuthorizedClientManager authorizedClientManager,
            BearerProvider forwardingBearerProvider) {
        return new SpringAddonsRestClientSupport(addonsProperties.getClient(), authorizedClientManager, forwardingBearerProvider);
    }

    @Conditional(IsServletWithWebClientCondition.class)
    @Bean
    SpringAddonsWebClientSupport webClientSupport(
            SpringAddonsOidcProperties addonsProperties,
            OAuth2AuthorizedClientManager authorizedClientManager,
            BearerProvider forwardingBearerProvider) {
        return new SpringAddonsWebClientSupport(addonsProperties.getClient(), authorizedClientManager, forwardingBearerProvider);
    }

    @ConditionalOnWebApplication(type = Type.REACTIVE)
    @Bean
    ReactiveSpringAddonsRestSupport reactiveWebClientSupport(
            SpringAddonsOidcProperties addonsProperties,
            ReactiveOAuth2AuthorizedClientManager authorizedClientManager,
            BearerProvider forwardingBearerProvider) {
        return new ReactiveSpringAddonsRestSupport(addonsProperties.getClient(), authorizedClientManager, forwardingBearerProvider);
    }
}
