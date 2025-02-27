package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultGrantedAuthoritiesMapperCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultReactiveOAuth2AuthorizedClientManagerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultReactiveOAuth2AuthorizedClientProviderCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsReactiveOauth2ClientCondition;

@Conditional({IsReactiveOauth2ClientCondition.class})
@AutoConfiguration
public class ReactiveSpringAddonsOAuth2AuthorizedClientBeans {

  @Conditional(DefaultReactiveOAuth2AuthorizedClientManagerCondition.class)
  @Bean
  ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
      ReactiveClientRegistrationRepository clientRegistrationRepository,
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
      ReactiveOAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider) {

    final var authorizedClientManager = new DefaultReactiveOAuth2AuthorizedClientManager(
        clientRegistrationRepository, authorizedClientRepository);
    authorizedClientManager.setAuthorizedClientProvider(oauth2AuthorizedClientProvider);

    return authorizedClientManager;
  }

  @Conditional(DefaultReactiveOAuth2AuthorizedClientProviderCondition.class)
  @Bean
  ReactiveOAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider(
      SpringAddonsOidcProperties addonsProperties,
      InMemoryReactiveClientRegistrationRepository clientRegistrationRepository) {
    return new PerRegistrationReactiveOAuth2AuthorizedClientProvider(clientRegistrationRepository,
        addonsProperties);
  }

  /**
   * @param authoritiesConverter the authorities converter to use (by default
   *        {@link ConfigurableClaimSetAuthoritiesConverter})
   * @return {@link GrantedAuthoritiesMapper} using the authorities converter in the context
   */
  @Conditional(DefaultGrantedAuthoritiesMapperCondition.class)
  @ConditionalOnMissingBean
  @Bean
  GrantedAuthoritiesMapper grantedAuthoritiesMapper(
      Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
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
