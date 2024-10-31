package com.c4_soft.springaddons.rest;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.service.annotation.HttpExchange;
import lombok.Data;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
@Data
@AutoConfiguration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.rest")
public class SpringAddonsRestProperties {
  /**
   * <p>
   * Configure Proxy-Authorization header for authentication on a HTTP or SOCKS proxy. This header
   * auto-configuration can be disable on each client.
   * </p>
   * <p>
   * HTTP_PROXY and NO_PROXY standard environment variable are used only if
   * "com.c4-soft.springaddons.rest.proxy.hostname" is left empty and
   * "com.c4-soft.springaddons.rest.proxy.enabled" is TRUE or null. In other words, if the standard
   * environment variables are correctly set, leaving "hostname" and "enabled" empty in
   * "springaddons" properties is probably the best option.
   * </p>
   */
  private ProxyProperties proxy = new ProxyProperties();

  /**
   * Expose {@link RestClient} or {@link WebClient} instances as named beans
   */
  private Map<String, RestClientProperties> client = new HashMap<>();

  public String getClientBeanName(String clientId) {
    if (!client.containsKey(clientId)) {
      return null;
    }
    final var clientProperties = client.get(clientId);
    return clientProperties.getBeanName()
        .orElse(clientProperties.isExposeBuilder() ? toCamelCase(clientId) + "Builder"
            : toCamelCase(clientId));
  }

  private static String toCamelCase(String in) {
    if (in == null) {
      return null;
    }
    if (!StringUtils.hasText(in)) {
      return "";
    }
    String[] words = in.split("[\\W_]+");
    StringBuilder builder = new StringBuilder();
    for (int i = 0; i < words.length; i++) {
      String word = words[i];
      if (i == 0) {
        word = word.isEmpty() ? word : word.toLowerCase();
      } else {
        word = word.isEmpty() ? word
            : Character.toUpperCase(word.charAt(0)) + word.substring(1).toLowerCase();
      }
      builder.append(word);
    }
    return builder.toString();
  }

  // FIXME: enable when a way is found to generate and register service proxies as beans.
  // For instance, have the HttpExchangeProxyFactoryBean definitions registered with a
  // BeanDefinitionRegistryPostProcessor

  // /**
  // * Expose {@link HttpExchange &#64;HttpExchange} proxies as named beans (generated using
  // * {@link HttpServiceProxyFactory})
  // */
  // private Map<String, RestServiceProperties> service = new HashMap<>();

  @Data
  public static class ProxyProperties {
    private boolean enabled = true;
    private String protocol = "http";
    private int port = 8080;
    private String username;
    private String password;
    private int connectTimeoutMillis = 10000;

    private Optional<String> host = Optional.empty();

    private String nonProxyHostsPattern;
  }

  @Data
  public static class RestClientProperties {
    /**
     * Base URI used to build the REST client ({@link RestClient} or {@link WebClient})
     */
    private Optional<String> baseUrl = Optional.empty();

    /**
     * Configure a {@link ClientHttpRequestInterceptor} or {@link ExchangeFilterFunction} to
     * authorize requests (add a Basic or Bearer header to each request)
     */
    private AuthorizationProperties authorization = new AuthorizationProperties();

    /**
     * Defines the type of the REST client. Default is {@link RestClient} in servlet applications
     * and {@link WebClient} in reactive ones.
     */
    private ClientType type = ClientType.DEFAULT;

    /**
     * If true, the Proxy-Authorization header is not automatically added to the requests of this
     * REST client.
     */
    private boolean ignoreHttpProxy = false;

    /**
     * If true, what is exposed as a bean is the pre-configured {@link RestClient.Builder} or
     * {@link WebClient.Builder}. This allows to add some more configuration. Don't forget to expose
     * the resulting {@link RestClient} or {@link WebClient} as a named bean if you intend to use it
     * as the REST client in an auto-configured {@link HttpExchange &#64;HttpExchange} proxy.
     */
    private boolean exposeBuilder = false;

    /**
     * <p>
     * Override the auto-configured bean name which defaults to the camelCase version of the
     * client-id, with the "Builder" suffix if expose-builder is true.
     * </p>
     * <p>
     * For instance, "com.c4-soft.springaddons.rest.client.machin-client" will create a bean named
     * machinClient or machinClientBuilder depending on
     * "com.c4-soft.springaddons.rest.client.machin-client.expose-builder" value.
     * </p>
     */
    private Optional<String> beanName = Optional.empty();

    public Optional<URL> getBaseUrl() {
      return baseUrl.map(t -> {
        try {
          return new URL(t);
        } catch (MalformedURLException e) {
          throw new RuntimeException(e);
        }
      });
    }

    @Data
    public static class AuthorizationProperties {

      private OAuth2Properties oauth2 = new OAuth2Properties();

      private BasicAuthProperties basic = new BasicAuthProperties();

      boolean isConfigured() {
        return oauth2.isConfigured() || basic.isConfigured();
      }

      boolean isConfValid() {
        return oauth2.isConfValid() && basic.isConfValid()
            && (!oauth2.isConfigured() || !basic.isConfigured());
      }

      @Data
      public static class OAuth2Properties {
        /**
         * <p>
         * If provided, it is used to get an access token from the
         * {@link OAuth2AuthorizedClientManager}.
         * </p>
         * <p>
         * Must reference a valid entry under spring.security.oauth2.client.registration
         * </p>
         * <p>
         * Mutually exclusive with forward-bearer property.
         * </p>
         */
        private Optional<String> oauth2RegistrationId = Optional.empty();

        /**
         * <p>
         * If true, the access token is taken from the {@link Authentication} in the security
         * context.
         * </p>
         * <p>
         * Mutually exclusive with auth2-registration-id property.
         * </p>
         */
        private boolean forwardBearer = false;

        boolean isConfigured() {
          return forwardBearer || oauth2RegistrationId.isPresent();
        }

        boolean isConfValid() {
          return !forwardBearer || oauth2RegistrationId.isEmpty();
        }
      }

      @Data
      public static class BasicAuthProperties {
        private Optional<String> username = Optional.empty();
        private Optional<String> password = Optional.empty();
        private Optional<Charset> charset = Optional.empty();
        private Optional<String> encodedCredentials = Optional.empty();

        boolean isConfigured() {
          return encodedCredentials.isPresent() || username.isPresent();
        }

        boolean isConfValid() {
          return encodedCredentials.isEmpty() || (username.isEmpty() && password.isEmpty());
        }
      }
    }

    public static enum ClientType {
      DEFAULT, REST_CLIENT, WEB_CLIENT;
    }
  }

  @Data
  public static class RestServiceProperties {
    /**
     * <p>
     * Name of a {@link RestClient} or {@link WebClient} bean.
     * </p>
     * Note that:
     * <ul>
     * <li>This bean does not have to be one of the auto-generated REST clients.</li>
     * <li>The value is a REST client <b>bean name</b>, not a "com.c4-soft.springaddons.rest.client"
     * key, which is the ID of for an auto-generated REST client (or builder) bean.</li>
     * <li>As a reminder, auto-generated REST client beans hare named with a camel-case version of
     * their ID. For instance "com.c4-soft.springaddons.rest.client.machin-client" properties would
     * create a bean named "machinClient"</li>
     * </ul>
     */
    private String clientBeanName;

    /**
     * Fully qualified class name of the {@link HttpExchange} to implement
     */
    private String httpExchangeClass;

    /**
     * <p>
     * Override the auto-configured bean name which defaults to the camelCase version of the
     * client-id.
     * </p>
     */
    private Optional<String> beanName = Optional.empty();
  }
}
