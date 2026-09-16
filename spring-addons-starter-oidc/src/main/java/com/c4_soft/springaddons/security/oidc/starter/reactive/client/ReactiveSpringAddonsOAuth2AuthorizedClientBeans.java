package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.HasOAuth2RegistrationWithGrantTypeCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultGrantedAuthoritiesMapperCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultReactiveOAuth2AuthorizedClientManagerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultReactiveOAuth2AuthorizedClientProviderCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultServerOAuth2AuthorizedClientRepositoryCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsReactiveOauth2ClientCondition;

@Conditional({IsReactiveOauth2ClientCondition.class})
@AutoConfiguration(
    beforeName = "org.springframework.boot.security.oauth2.client.autoconfigure.reactive.ReactiveOAuth2ClientWebSecurityAutoConfiguration")
public class ReactiveSpringAddonsOAuth2AuthorizedClientBeans {

  /**
   * <p>
   * Spring Boot default is an {@code AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository}
   * backed by an {@code InMemoryReactiveOAuth2AuthorizedClientService}: tokens are kept in a map
   * local to the JVM, they are not replicated to the other instances of the application and they
   * are not evicted when the user session expires.
   * </p>
   * <p>
   * Storing the authorized clients in the web session instead is what a BFF (or any OAuth2 client
   * with {@code oauth2Login}) needs: tokens follow the session, which means that they are
   * replicated by Spring Session and released when the session is closed.
   * </p>
   *
   * @return {@link WebSessionServerOAuth2AuthorizedClientRepository}, registered only when at least
   *         one registration uses the {@code authorization_code} flow
   */
  @Conditional(DefaultServerOAuth2AuthorizedClientRepositoryCondition.class)
  @Bean
  ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
    return new WebSessionServerOAuth2AuthorizedClientRepository();
  }

  /**
   * <p>
   * The {@link ReactiveOAuth2AuthorizedClientManager} matching the flows declared with
   * {@code spring.security.oauth2.client.registration.*} properties:
   * </p>
   * <ul>
   * <li>only {@code authorization_code} registrations: a
   * {@link DefaultReactiveOAuth2AuthorizedClientManager}, which requires a
   * {@code ServerWebExchange} and stores the authorized clients in the
   * {@link ServerOAuth2AuthorizedClientRepository}</li>
   * <li>no {@code authorization_code} registration (a resource server consuming another resource
   * server with {@code client_credentials}, for instance): an
   * {@link AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager}, which does not need any
   * exchange and stores the authorized clients in the
   * {@link ReactiveOAuth2AuthorizedClientService}, so that tokens are reused across requests
   * instead of being requested again for each of them</li>
   * <li>both: a {@link PerRegistrationReactiveOAuth2AuthorizedClientManager} delegating to one of
   * the two above, depending on the flow of the registration to authorize</li>
   * </ul>
   * <p>
   * The {@link ReactiveOAuth2AuthorizationFailureHandler} in the context, if any, is applied only
   * to the manager storing the authorized clients in the
   * {@link ServerOAuth2AuthorizedClientRepository}: the default one (auto-configured by
   * {@code spring-addons-starter-rest}) removes authorized clients from that repository.
   * </p>
   *
   * @param environment used to resolve the flow of each registration
   * @param clientRegistrationRepository the client registrations
   * @param authorizedClientRepository required only if some registration uses
   *        {@code authorization_code}
   * @param authorizedClientService required only if some registration uses another flow
   * @param oauth2AuthorizedClientProvider the authorized client provider to use (by default
   *        {@link PerRegistrationReactiveOAuth2AuthorizedClientProvider})
   * @param authorizationFailureHandler the failure handler to apply to the repository based manager
   * @return the authorized client manager to use
   */
  @Conditional(DefaultReactiveOAuth2AuthorizedClientManagerCondition.class)
  @Bean
  ReactiveOAuth2AuthorizedClientManager authorizedClientManager(Environment environment,
      ReactiveClientRegistrationRepository clientRegistrationRepository,
      ObjectProvider<ServerOAuth2AuthorizedClientRepository> authorizedClientRepository,
      ObjectProvider<ReactiveOAuth2AuthorizedClientService> authorizedClientService,
      ReactiveOAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider,
      Optional<ReactiveOAuth2AuthorizationFailureHandler> authorizationFailureHandler) {

    final var grantTypes = new HashSet<>(HasOAuth2RegistrationWithGrantTypeCondition
        .authorizationGrantTypesByRegistrationId(environment).values());
    final var hasAuthorizationCodeRegistration =
        grantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE);
    grantTypes.remove(AuthorizationGrantType.AUTHORIZATION_CODE);

    if (grantTypes.isEmpty()) {
      return sessionScopedManager(clientRegistrationRepository, authorizedClientRepository,
          oauth2AuthorizedClientProvider, authorizationFailureHandler);
    }

    if (!hasAuthorizationCodeRegistration) {
      return applicationScopedManager(clientRegistrationRepository, authorizedClientService,
          oauth2AuthorizedClientProvider);
    }

    return new PerRegistrationReactiveOAuth2AuthorizedClientManager(clientRegistrationRepository,
        sessionScopedManager(clientRegistrationRepository, authorizedClientRepository,
            oauth2AuthorizedClientProvider, authorizationFailureHandler),
        applicationScopedManager(clientRegistrationRepository, authorizedClientService,
            oauth2AuthorizedClientProvider));
  }

  private static ReactiveOAuth2AuthorizedClientManager sessionScopedManager(
      ReactiveClientRegistrationRepository clientRegistrationRepository,
      ObjectProvider<ServerOAuth2AuthorizedClientRepository> authorizedClientRepository,
      ReactiveOAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider,
      Optional<ReactiveOAuth2AuthorizationFailureHandler> authorizationFailureHandler) {

    final var authorizedClientManager = new DefaultReactiveOAuth2AuthorizedClientManager(
        clientRegistrationRepository, authorizedClientRepository.getObject());
    authorizedClientManager.setAuthorizedClientProvider(oauth2AuthorizedClientProvider);
    authorizationFailureHandler.ifPresent(authorizedClientManager::setAuthorizationFailureHandler);

    return authorizedClientManager;
  }

  private static ReactiveOAuth2AuthorizedClientManager applicationScopedManager(
      ReactiveClientRegistrationRepository clientRegistrationRepository,
      ObjectProvider<ReactiveOAuth2AuthorizedClientService> authorizedClientService,
      ReactiveOAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider) {

    final var authorizedClientManager =
        new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
            clientRegistrationRepository, authorizedClientService.getObject());
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
