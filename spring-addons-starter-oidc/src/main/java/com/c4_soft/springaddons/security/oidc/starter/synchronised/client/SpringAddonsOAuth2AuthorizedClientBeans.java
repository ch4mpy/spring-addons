package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.HasTokenEdpointParametersPropertiesCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultGrantedAuthoritiesMapperCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultOAuth2AuthorizedClientManagerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultOAuth2AuthorizedClientProviderCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsServletOauth2ClientCondition;

@Conditional({ IsServletOauth2ClientCondition.class, HasTokenEdpointParametersPropertiesCondition.class })
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
        return new PerRegistrationOAuth2AuthorizedClientProvider(clientRegistrationRepository, addonsProperties, Map.of());
    }

    /**
     * @param authoritiesConverter the authorities converter to use (by default {@link ConfigurableClaimSetAuthoritiesConverter})
     * @return {@link GrantedAuthoritiesMapper} using the authorities converter in the context
     */
    @Conditional(DefaultGrantedAuthoritiesMapperCondition.class)
    @Bean
    GrantedAuthoritiesMapper grantedAuthoritiesMapper(Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority oidcAuth) {
                    mappedAuthorities.addAll(authoritiesConverter.convert(oidcAuth.getIdToken().getClaims()));

                } else if (authority instanceof OAuth2UserAuthority oauth2Auth) {
                    mappedAuthorities.addAll(authoritiesConverter.convert(oauth2Auth.getAttributes()));

                }
            });

            return mappedAuthorities;
        };
    }
}
