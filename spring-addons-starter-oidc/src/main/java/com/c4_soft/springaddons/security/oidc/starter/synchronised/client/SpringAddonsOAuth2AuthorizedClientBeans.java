package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.HasOAuth2RegistrationWithGrantTypeCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultGrantedAuthoritiesMapperCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultOAuth2AuthorizedClientManagerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultOAuth2AuthorizedClientProviderCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultOAuth2AuthorizedClientRepositoryCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsServletOauth2ClientCondition;

@Conditional({IsServletOauth2ClientCondition.class})
@AutoConfiguration(
    beforeName = "org.springframework.boot.security.oauth2.client.autoconfigure.servlet.OAuth2ClientWebSecurityAutoConfiguration")
public class SpringAddonsOAuth2AuthorizedClientBeans {

  /**
   * <p>
   * Spring Boot default is an {@code AuthenticatedPrincipalOAuth2AuthorizedClientRepository} backed
   * by an {@code InMemoryOAuth2AuthorizedClientService}: tokens are kept in a map local to the JVM,
   * they are not replicated to the other instances of the application and they are not evicted when
   * the user session expires.
   * </p>
   * <p>
   * Storing the authorized clients in the HTTP session instead is what a BFF (or any OAuth2 client
   * with {@code oauth2Login}) needs: tokens follow the session, which means that they are
   * replicated by Spring Session and released when the session is closed.
   * </p>
   *
   * @return {@link HttpSessionOAuth2AuthorizedClientRepository}, registered only when at least one
   *         registration uses the {@code authorization_code} flow
   */
  @Conditional(DefaultOAuth2AuthorizedClientRepositoryCondition.class)
  @Bean
  OAuth2AuthorizedClientRepository authorizedClientRepository() {
    return new HttpSessionOAuth2AuthorizedClientRepository();
  }

  /**
   * <p>
   * The {@link OAuth2AuthorizedClientManager} matching the flows declared with
   * {@code spring.security.oauth2.client.registration.*} properties:
   * </p>
   * <ul>
   * <li>only {@code authorization_code} registrations: a
   * {@link DefaultOAuth2AuthorizedClientManager}, which requires an {@code HttpServletRequest} and
   * stores the authorized clients in the {@link OAuth2AuthorizedClientRepository}</li>
   * <li>no {@code authorization_code} registration (a resource server consuming another resource
   * server with {@code client_credentials}, for instance): an
   * {@link AuthorizedClientServiceOAuth2AuthorizedClientManager}, which does not need any request
   * and stores the authorized clients in the {@link OAuth2AuthorizedClientService}, so that tokens
   * are reused across requests instead of being requested again for each of them</li>
   * <li>both: a {@link PerRegistrationOAuth2AuthorizedClientManager} delegating to one of the two
   * above, depending on the flow of the registration to authorize</li>
   * </ul>
   * <p>
   * The {@link OAuth2AuthorizationFailureHandler} in the context, if any, is applied only to the
   * manager storing the authorized clients in the {@link OAuth2AuthorizedClientRepository}: the
   * default one (auto-configured by {@code spring-addons-starter-rest}) removes authorized clients
   * from that repository, while the
   * {@link AuthorizedClientServiceOAuth2AuthorizedClientManager} already removes them from the
   * {@link OAuth2AuthorizedClientService} on its own.
   * </p>
   *
   * @param environment used to resolve the flow of each registration
   * @param clientRegistrationRepository the client registrations
   * @param authorizedClientRepository required only if some registration uses
   *        {@code authorization_code}
   * @param authorizedClientService required only if some registration uses another flow
   * @param oauth2AuthorizedClientProvider the authorized client provider to use (by default
   *        {@link PerRegistrationOAuth2AuthorizedClientProvider})
   * @param authorizationFailureHandler the failure handler to apply to the repository based manager
   * @return the authorized client manager to use
   */
  @Conditional(DefaultOAuth2AuthorizedClientManagerCondition.class)
  @Bean
  OAuth2AuthorizedClientManager authorizedClientManager(Environment environment,
      ClientRegistrationRepository clientRegistrationRepository,
      ObjectProvider<OAuth2AuthorizedClientRepository> authorizedClientRepository,
      ObjectProvider<OAuth2AuthorizedClientService> authorizedClientService,
      OAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider,
      Optional<OAuth2AuthorizationFailureHandler> authorizationFailureHandler) {

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

    return new PerRegistrationOAuth2AuthorizedClientManager(clientRegistrationRepository,
        sessionScopedManager(clientRegistrationRepository, authorizedClientRepository,
            oauth2AuthorizedClientProvider, authorizationFailureHandler),
        applicationScopedManager(clientRegistrationRepository, authorizedClientService,
            oauth2AuthorizedClientProvider));
  }

  private static OAuth2AuthorizedClientManager sessionScopedManager(
      ClientRegistrationRepository clientRegistrationRepository,
      ObjectProvider<OAuth2AuthorizedClientRepository> authorizedClientRepository,
      OAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider,
      Optional<OAuth2AuthorizationFailureHandler> authorizationFailureHandler) {

    final var authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
        clientRegistrationRepository, authorizedClientRepository.getObject());
    authorizedClientManager.setAuthorizedClientProvider(oauth2AuthorizedClientProvider);
    authorizationFailureHandler.ifPresent(authorizedClientManager::setAuthorizationFailureHandler);

    return authorizedClientManager;
  }

  private static OAuth2AuthorizedClientManager applicationScopedManager(
      ClientRegistrationRepository clientRegistrationRepository,
      ObjectProvider<OAuth2AuthorizedClientService> authorizedClientService,
      OAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider) {

    final var authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(
        clientRegistrationRepository, authorizedClientService.getObject());
    authorizedClientManager.setAuthorizedClientProvider(oauth2AuthorizedClientProvider);

    return authorizedClientManager;
  }

  @Conditional(DefaultOAuth2AuthorizedClientProviderCondition.class)
  @Bean
  OAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider(
      SpringAddonsOidcProperties addonsProperties,
      ClientRegistrationRepository clientRegistrationRepository) {
    return new PerRegistrationOAuth2AuthorizedClientProvider(clientRegistrationRepository,
        addonsProperties);
  }

  /**
   * @param authoritiesConverter the authorities converter to use (by default
   *        {@link ConfigurableClaimSetAuthoritiesConverter})
   * @return {@link GrantedAuthoritiesMapper} using the authorities converter in the context
   */
  @Conditional(DefaultGrantedAuthoritiesMapperCondition.class)
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
