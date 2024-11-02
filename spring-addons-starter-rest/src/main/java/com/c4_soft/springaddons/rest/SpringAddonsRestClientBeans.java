package com.c4_soft.springaddons.rest;

import java.net.URL;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.web.client.RestClient;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.AuthorizationProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientType;
import lombok.Data;
import lombok.Setter;

/**
 * Applied only in servlet applications.
 * 
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
@ConditionalOnWebApplication(type = Type.SERVLET)
@AutoConfiguration
public class SpringAddonsRestClientBeans {

  @Bean
  SpringAddonsRestClientBeanDefinitionRegistryPostProcessor springAddonsRestClientBeanDefinitionRegistryPostProcessor(
      Environment environment) {
    return new SpringAddonsRestClientBeanDefinitionRegistryPostProcessor(environment);
  }

  /**
   * <p>
   * Post process the {@link BeanDefinitionRegistry} to add a {@link RestClient} (or
   * {@link RestClient.builder}) bean definitions for each entry in
   * "com.c4-soft.springaddons.rest.client".
   * </p>
   * 
   * <p>
   * The bean names are by default the camelCase transformation of the client-id, suffixed with
   * "Builder" if the expose-builder property is true.
   * </p>
   * 
   * @author ch4mp&#64;c4-soft.com
   */
  static class SpringAddonsRestClientBeanDefinitionRegistryPostProcessor
      implements BeanDefinitionRegistryPostProcessor {

    private final SpringAddonsRestProperties restProperties;
    private final SystemProxyProperties systemProxyProperties;

    @SuppressWarnings("unchecked")
    public SpringAddonsRestClientBeanDefinitionRegistryPostProcessor(Environment environment) {
      this.restProperties = Binder.get(environment)
          .bind("com.c4-soft.springaddons.rest", SpringAddonsRestProperties.class)
          .orElseThrow(() -> new RestMisconfigurationException(
              "Could not read spring-addons REST properties"));

      final var httpProxy = Optional
          .ofNullable(Binder.get(environment).bind("http-proxy", String.class).orElse(null));
      final var noProxy = Binder.get(environment).bind("no-proxy", List.class).orElse(List.of());
      this.systemProxyProperties = new SystemProxyProperties(httpProxy, noProxy);
    }

    @Override
    public void postProcessBeanDefinitionRegistry(@NonNull BeanDefinitionRegistry registry)
        throws BeansException {

      restProperties.getClient().entrySet().stream()
          .filter(e -> ClientType.REST_CLIENT.equals(e.getValue().getType())
              || ClientType.DEFAULT.equals(e.getValue().getType()))
          .forEach(e -> {
            final var builder = e.getValue().isExposeBuilder()
                ? BeanDefinitionBuilder.genericBeanDefinition(RestClientBuilderFactoryBean.class)
                : BeanDefinitionBuilder.genericBeanDefinition(RestClientFactoryBean.class);
            builder.addPropertyValue("systemProxyProperties", systemProxyProperties);
            builder.addPropertyValue("restProperties", restProperties);
            builder.addAutowiredProperty("authorizedClientManager");
            builder.addAutowiredProperty("authorizedClientRepository");
            builder.addPropertyValue("clientId", e.getKey());
            registry.registerBeanDefinition(restProperties.getClientBeanName(e.getKey()),
                builder.getBeanDefinition());
          });

      /*
       * FIXME: for some reason, this doesn't work: the clientRegistrationRepo is initialized before
       * OAuth2 client properties are resolved and the HttpExchangeProxyFactoryBean<T> named beans
       * are not resolved when injecting T in components
       */
      // restProperties.getService().entrySet().stream().forEach(e -> {
      // final var builder =
      // BeanDefinitionBuilder.genericBeanDefinition(HttpExchangeProxyFactoryBean.class);
      // try {
      // builder.addConstructorArgValue(Class.forName(e.getValue().getHttpExchangeClass()));
      // } catch (ClassNotFoundException e1) {
      // throw new RestMisconfigurationConfigurationException(
      // "Unknown class %s for REST service to auto-configure"
      // .formatted(e.getValue().getHttpExchangeClass()));
      // }
      // builder.addConstructorArgReference(e.getValue().getClientBeanName());
      // final var beanName = e.getValue().getBeanName().orElse(toCamelCase(e.getKey()));
      // registry.registerBeanDefinition(beanName, builder.getBeanDefinition());
      // });

    }
  }

  @Setter
  public static class RestClientFactoryBean implements FactoryBean<RestClient> {
    private String clientId;
    private SystemProxyProperties systemProxyProperties;
    private SpringAddonsRestProperties restProperties;
    private Optional<OAuth2AuthorizedClientManager> authorizedClientManager = Optional.empty();
    private Optional<OAuth2AuthorizedClientRepository> authorizedClientRepository =
        Optional.empty();

    @Override
    @Nullable
    public RestClient getObject() throws Exception {
      final var builderFactoryBean = new RestClientBuilderFactoryBean();
      builderFactoryBean.setClientId(clientId);
      builderFactoryBean.setSystemProxyProperties(systemProxyProperties);
      builderFactoryBean.setRestProperties(restProperties);
      builderFactoryBean.setAuthorizedClientManager(authorizedClientManager);
      builderFactoryBean.setAuthorizedClientRepository(authorizedClientRepository);
      return Optional.ofNullable(builderFactoryBean.getObject()).map(RestClient.Builder::build)
          .orElse(null);
    }

    @Override
    @Nullable
    public Class<?> getObjectType() {
      return RestClient.class;
    }
  }

  @Data
  public static class RestClientBuilderFactoryBean implements FactoryBean<RestClient.Builder> {
    private String clientId;
    private SystemProxyProperties systemProxyProperties = new SystemProxyProperties();
    private SpringAddonsRestProperties restProperties = new SpringAddonsRestProperties();
    private Optional<OAuth2AuthorizedClientManager> authorizedClientManager;
    private Optional<OAuth2AuthorizedClientRepository> authorizedClientRepository;


    @Override
    @Nullable
    public RestClient.Builder getObject() throws Exception {
      final var clientProps = Optional.ofNullable(restProperties.getClient().get(clientId))
          .orElseThrow(() -> new RestConfigurationNotFoundException(clientId));

      final var builder = RestClient.builder();

      // Handle HTTP or SOCK proxy and set timeouts & chunck-size
      builder.requestFactory(
          new SpringAddonsClientHttpRequestFactory(systemProxyProperties, clientProps.getHttp()));

      clientProps.getBaseUrl().map(URL::toString).ifPresent(builder::baseUrl);

      setAuthorizationHeader(builder, clientProps.getAuthorization(), clientId);

      return builder;
    }

    @Override
    @Nullable
    public Class<?> getObjectType() {
      return RestClient.Builder.class;
    }

    protected void setAuthorizationHeader(RestClient.Builder clientBuilder,
        AuthorizationProperties authProps, String clientId) {
      if (authProps.getOauth2().isConfigured() && authProps.getBasic().isConfigured()) {
        throw new RestMisconfigurationException(
            "REST authorization configuration for %s can be made for either OAuth2 or Basic, but not both at a time"
                .formatted(clientId));
      }
      if (authProps.getOauth2().isConfigured()) {
        setBearerAuthorizationHeader(clientBuilder, authProps.getOauth2(), clientId);
      } else if (authProps.getBasic().isConfigured()) {
        setBasicAuthorizationHeader(clientBuilder, authProps.getBasic(), clientId);
      }
    }

    protected void setBearerAuthorizationHeader(RestClient.Builder clientBuilder,
        AuthorizationProperties.OAuth2Properties oauth2Props, String clientId) {
      if (!oauth2Props.isConfValid()) {
        throw new RestMisconfigurationException(
            "REST OAuth2 authorization configuration for %s can be made for either a registration-id or resource server Bearer forwarding, but not both at a time"
                .formatted(clientId));
      }
      if (oauth2Props.getOauth2RegistrationId().isPresent()) {
        clientBuilder.requestInterceptor(
            registrationClientHttpRequestInterceptor(oauth2Props.getOauth2RegistrationId().get()));
      } else if (oauth2Props.isForwardBearer()) {
        clientBuilder.requestInterceptor(forwardingClientHttpRequestInterceptor());
      }
    }

    protected ClientHttpRequestInterceptor forwardingClientHttpRequestInterceptor() {
      return (HttpRequest request, byte[] body, ClientHttpRequestExecution execution) -> {
        final var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof OAuth2Token oauth2Token) {
          request.getHeaders().setBearerAuth(oauth2Token.getTokenValue());
        }
        return execution.execute(request, body);
      };
    }

    protected ClientHttpRequestInterceptor registrationClientHttpRequestInterceptor(
        String registrationId) {
      if (authorizedClientManager.isEmpty()) {
        throw new RestMisconfigurationException(
            "OAuth2 client missconfiguration. Can't setup an OAuth2 Bearer request interceptor because there is no authorizedClientManager bean.");
      }
      final var interceptor = new OAuth2ClientHttpRequestInterceptor(authorizedClientManager.get());
      interceptor.setClientRegistrationIdResolver((HttpRequest request) -> registrationId);
      authorizedClientRepository
          .map(OAuth2ClientHttpRequestInterceptor::authorizationFailureHandler)
          .ifPresent(interceptor::setAuthorizationFailureHandler);
      return interceptor;
    }

    protected void setBasicAuthorizationHeader(RestClient.Builder clientBuilder,
        AuthorizationProperties.BasicAuthProperties authProps, String clientId) {
      if (authProps.getEncodedCredentials().isPresent()) {
        if (authProps.getUsername().isPresent() || authProps.getPassword().isPresent()
            || authProps.getCharset().isPresent()) {
          throw new RestMisconfigurationException(
              "REST Basic authorization for %s is misconfigured: when encoded-credentials is provided, username, password and charset must be absent."
                  .formatted(clientId));
        }
      } else {
        if (authProps.getUsername().isEmpty() || authProps.getPassword().isEmpty()) {
          throw new RestMisconfigurationException(
              "REST Basic authorization for %s is misconfigured: when encoded-credentials is empty, username & password are required."
                  .formatted(clientId));
        }
      }
      clientBuilder.requestInterceptor((request, body, execution) -> {
        authProps.getEncodedCredentials().ifPresent(request.getHeaders()::setBasicAuth);
        authProps.getCharset().ifPresentOrElse(
            charset -> request.getHeaders().setBasicAuth(authProps.getUsername().get(),
                authProps.getPassword().get(), charset),
            () -> request.getHeaders().setBasicAuth(authProps.getUsername().get(),
                authProps.getPassword().get()));
        return execution.execute(request, body);
      });
    }

  }

}
