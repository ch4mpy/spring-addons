package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultReactiveOAuth2AuthorizedClientManagerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultReactiveOAuth2AuthorizedClientProviderCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsReactiveOauth2ClientCondition;

@Conditional(IsReactiveOauth2ClientCondition.class)
@AutoConfiguration
public class ReactiveSpringAddonsOAuth2AuthorizedClientBeans {

    @Conditional(DefaultReactiveOAuth2AuthorizedClientManagerCondition.class)
    @Bean
    ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
            ReactiveClientRegistrationRepository clientRegistrationRepository,
            ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
            ReactiveOAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider) {

        final var authorizedClientManager = new DefaultReactiveOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(oauth2AuthorizedClientProvider);

        return authorizedClientManager;
    }

    @Conditional(DefaultReactiveOAuth2AuthorizedClientProviderCondition.class)
    @Bean
    ReactiveOAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider(
            SpringAddonsOidcProperties addonsProperties,
            InMemoryReactiveClientRegistrationRepository clientRegistrationRepository) {
        return new PerRegistrationReactiveOAuth2AuthorizedClientProvider(clientRegistrationRepository, addonsProperties);
    }

}
