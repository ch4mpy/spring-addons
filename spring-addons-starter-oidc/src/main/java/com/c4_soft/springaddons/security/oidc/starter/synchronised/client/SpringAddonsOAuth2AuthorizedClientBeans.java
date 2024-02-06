package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultOAuth2AuthorizedClientManagerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultOAuth2AuthorizedClientProviderCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsServletOauth2ClientCondition;

@Conditional(IsServletOauth2ClientCondition.class)
@AutoConfiguration
public class SpringAddonsOAuth2AuthorizedClientBeans {

    @Conditional(DefaultOAuth2AuthorizedClientManagerCondition.class)
    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            OAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider) {

        final var authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(oauth2AuthorizedClientProvider);

        return authorizedClientManager;
    }

    @Conditional(DefaultOAuth2AuthorizedClientProviderCondition.class)
    @Bean
    OAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider(
            SpringAddonsOidcProperties addonsProperties,
            InMemoryClientRegistrationRepository clientRegistrationRepository) {
        return new PerRegistrationOAuth2AuthorizedClientProvider(clientRegistrationRepository, addonsProperties);
    }
}
