package com.c4_soft.springaddons.rest.synchronised;

import java.util.List;
import java.util.Optional;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.lang.NonNull;
import org.springframework.web.reactive.function.client.WebClient;
import com.c4_soft.springaddons.rest.AbstractWebClientBuilderFactoryBean;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientType;
import com.c4_soft.springaddons.rest.SystemProxyProperties;

/**
 * <p>
 * Post process the {@link BeanDefinitionRegistry} to add a {@link WebClient} (or
 * {@link WebClient.Builder}) bean definitions for each entry in
 * "com.c4-soft.springaddons.rest.client".
 * </p>
 * 
 * <p>
 * Bean definitions include a base URI, header and {@link ReactorClientHttpConnector} for HTTP or
 * SOCKS proxy, as well as exchange function for Basic or OAuth2 (Bearer) authorization.
 * </p>
 * 
 * <p>
 * The bean names are by default the camelCase transformation of the client-id, suffixed with
 * "Builder" if the expose-builder property is true.
 * </p>
 * 
 * @author ch4mp&#64;c4-soft.com
 */
public class SpringAddonsServletWebClientBeanDefinitionRegistryPostProcessor
    implements BeanDefinitionRegistryPostProcessor {

  private final SpringAddonsRestProperties restProperties;
  private final SystemProxyProperties systemProxyProperties;

  @SuppressWarnings("unchecked")
  public SpringAddonsServletWebClientBeanDefinitionRegistryPostProcessor(Environment environment) {
    this.restProperties = Binder.get(environment)
        .bind("com.c4-soft.springaddons.rest", SpringAddonsRestProperties.class)
        .orElseThrow(() -> new RestMisconfigurationException(
            "Could not read spring-addons REST properties"));

    final var httpProxy =
        Optional.ofNullable(Binder.get(environment).bind("http-proxy", String.class).orElse(null));
    final var noProxy = Binder.get(environment).bind("no-proxy", List.class).orElse(List.of());
    this.systemProxyProperties = new SystemProxyProperties(httpProxy, noProxy);
  }

  @Override
  public void postProcessBeanDefinitionRegistry(@NonNull BeanDefinitionRegistry registry)
      throws BeansException {

    restProperties.getClient().entrySet().stream()
        .filter(e -> ClientType.WEB_CLIENT.equals(e.getValue().getType())).forEach(e -> {
          final var builder = e.getValue().isExposeBuilder()
              ? BeanDefinitionBuilder
                  .genericBeanDefinition(ServletWebClientBuilderFactoryBean.class)
              : BeanDefinitionBuilder.genericBeanDefinition(ServletWebClientFactoryBean.class);
          builder.addPropertyValue(AbstractWebClientBuilderFactoryBean.Fields.systemProxyProperties,
              systemProxyProperties);
          builder.addPropertyValue(AbstractWebClientBuilderFactoryBean.Fields.restProperties,
              restProperties);
          builder.addAutowiredProperty(AbstractWebClientBuilderFactoryBean.Fields.webClientBuilder);
          builder.addAutowiredProperty("authorizedClientManager");
          builder.addPropertyValue(AbstractWebClientBuilderFactoryBean.Fields.clientId, e.getKey());
          registry.registerBeanDefinition(restProperties.getClientBeanName(e.getKey()),
              builder.getBeanDefinition());
        });

    /*
     * FIXME: for some reason, registering HttpExchangeProxyFactoryBean<T> definitions doesn't work:
     * the clientRegistrationRepo is initialized before OAuth2 client properties are resolved and
     * the HttpExchangeProxyFactoryBean<T> named beans are not resolved when injecting T in
     * components
     */

  }
}
