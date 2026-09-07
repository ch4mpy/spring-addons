package com.c4_soft.springaddons.rest;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.http.client.JettyClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.service.annotation.HttpExchange;
import lombok.Data;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Data
@AutoConfiguration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.rest")
public class SpringAddonsRestProperties {

  /**
   * Expose {@link RestClient} or {@link WebClient} instances as named beans
   */
  private Map<String, RestClientProperties> client = new HashMap<>();

  /**
   * <p>
   * Backs {@code @ImportHttpServices} HTTP Service groups with an already auto-configured
   * REST client (see {@link #client}), so that the group's proxies use the same base URL, headers
   * and authorization as the referenced client, and a request factory / connector built from the
   * same configuration (which may or may not reuse context-provided HTTP client beans depending on
   * whether customization is required).
   * </p><p>
   * The map key is the HTTP Service group name (the {@code group} attribute of
   * {@code @ImportHttpServices}). Groups not listed here are left to Spring Boot's own
   * resolution.
   * </p>
   */
  private Map<String, RestGroupProperties> group = new HashMap<>();

  // FIXME: enable when a way is found to generate and register service proxies as beans.
  // For instance, have the HttpExchangeProxyFactoryBean definitions registered with a
  // BeanDefinitionRegistryPostProcessor

  // /**
  // * Expose {@link HttpExchange &#64;HttpExchange} proxies as named beans (generated using
  // * {@link HttpServiceProxyFactory})
  // */
  // private Map<String, RestServiceProperties> service = new HashMap<>();

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
     * Configure the internal {@link SimpleClientHttpRequestFactory} (auto-configure the underlying
     * HTTP client). Honored only by the {@link RestClient}.
     */
    private ClientHttpRequestFactoryProperties http = new ClientHttpRequestFactoryProperties();

    /**
     * Defines the type of the REST client. Default is {@link RestClient} in servlet applications
     * and {@link WebClient} in reactive ones.
     */
    private ClientType type = ClientType.DEFAULT;

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

    /**
     * Some static headers to add to all requests sent by this client (for instance an API key). The
     * key is the header name. If the value contains several entries, the header is set several
     * times.
     */
    private Map<String, List<String>> headers = new HashMap<>();

    /**
     * If provided, configures the RestClient / WebClient to use the provided SSL bundle. This
     * bundle should contain material to trust when establishing the connection to the consumed REST
     * API.
     */
    private Optional<String> sslBundle = Optional.empty();

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

        public boolean isConfigured() {
          return forwardBearer || oauth2RegistrationId.isPresent();
        }

        public boolean isConfValid() {
          return !forwardBearer || oauth2RegistrationId.isEmpty();
        }
      }

      @Data
      public static class BasicAuthProperties {
        private Optional<String> username = Optional.empty();
        private Optional<String> password = Optional.empty();
        private Optional<Charset> charset = Optional.empty();
        private Optional<String> encodedCredentials = Optional.empty();

        public boolean isConfigured() {
          return encodedCredentials.isPresent() || username.isPresent();
        }

        public boolean isConfValid() {
          return encodedCredentials.isEmpty() || (username.isEmpty() && password.isEmpty());
        }
      }
    }

    @Data
    public static class ClientHttpRequestFactoryProperties {
      /**
       * <p>
       * Configure Proxy-Authorization header for authentication on a HTTP or SOCKS proxy. This
       * header auto-configuration can be disable on each client.
       * </p>
       * <p>
       * HTTP_PROXY and NO_PROXY standard environment variable are used only if
       * "com.c4-soft.springaddons.rest.proxy.hostname" is left empty and
       * "com.c4-soft.springaddons.rest.proxy.enabled" is TRUE or null. In other words, if the
       * standard environment variables are correctly set, leaving "proxy" properties empty here is
       * probably the best option.
       * </p>
       */
      private ProxyProperties proxy = new ProxyProperties();

      /**
       * Connection timeout in milliseconds.
       */
      private Optional<Integer> connectTimeoutMillis = Optional.empty();

      /**
       * Read timeout in milliseconds.
       */
      private Optional<Integer> readTimeoutMillis = Optional.empty();

      /**
       * Which {@link ClientHttpRequestFactory} implementation to use.
       * <ul>
       * <li>FROM_CONTEXT (default) reuses the {@code ClientHttpRequestFactoryBuilder} bean provided by Spring Boot,
       * copying and enriching its config with spring-addons one (proxy, timeouts, SSL, protocol version,
       * virtual threads, consumer bean). If a customization is required and the context builder is neither
       * HttpComponents, JDK nor Jetty, a {@link com.c4_soft.springaddons.rest.RestMisconfigurationException}
       * is thrown.</li>
       * <li>HTTP_COMPONENTS forces an Apache {@link HttpComponentsClientHttpRequestFactory}, ignoring
       * the context builder type. Requires org.apache.httpcomponents.client5:httpclient5 to be on the
       * class-path</li>
       * <li>JETTY forces a {@link JettyClientHttpRequestFactory}, ignoring the context builder type.
       * Requires org.eclipse.jetty:jetty-client to be on the class-path</li>
       * <li>JDK forces a {@link JdkClientHttpRequestFactory}, ignoring the context builder type.</li>
       * </ul>
       */
      private ClientHttpRequestFactoryImpl clientHttpRequestFactoryImpl =
          ClientHttpRequestFactoryImpl.FROM_CONTEXT;

      /**
       * If false, SSL certificate validation is disabled, which can be handy with self-signed
       * certificates on a private network. True by default. Note that, in the case with
       * JdkClientHttpRequestFactory only the root authority check is disabled, meaning that the
       * self-signed certificate CN claim must be correctly set.
       */
      private boolean sslCertificatesValidationEnabled = true;

      /**
       * HTTP protocol version to use. Honored by the JDK and JETTY implementations (ignored by
       * HTTP_COMPONENTS, whose classic client is HTTP/1.1 only). For JETTY, HTTP_2 requires
       * org.eclipse.jetty.http2:jetty-http2-client and jetty-http2-client-transport on the
       * class-path. When empty, the underlying client default is used.
       */
      private Optional<java.net.http.HttpClient.Version> httpProtocolVersion = Optional.empty();

      /**
       * If true, the application task executor (the {@code applicationTaskExecutor} bean, which
       * runs on virtual threads when {@code spring.threads.virtual.enabled} is true) is set on the
       * underlying client. Honored by the JDK and JETTY implementations (the classic Apache client
       * runs on the calling thread, so HTTP_COMPONENTS ignores it). When empty, defaults to the
       * value of {@code spring.threads.virtual.enabled}.
       */
      private Optional<Boolean> useVirtualThreads = Optional.empty();

      /**
       * Name of a {@link java.util.function.Consumer} bean applied to the underlying client builder
       * of the configured client-http-request-factory-impl just before the request factory is
       * built. Enables configuration that is not exposed as properties. The expected consumed type
       * depends on the implementation: {@code java.net.http.HttpClient.Builder} for JDK,
       * {@code org.apache.hc.client5.http.impl.classic.HttpClientBuilder} for HTTP_COMPONENTS and
       * {@code org.eclipse.jetty.client.HttpClient} for JETTY.
       */
      private Optional<String> httpClientBuilderConsumerBean = Optional.empty();

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

      /**
       * Implementation used as underlying {@link ClientHttpRequestFactory}. it is configured with
       * HTTP proxy settings (if any provided as properties or environment variables) and timeouts.
       */
      public static enum ClientHttpRequestFactoryImpl {
        /**
         * <p>
         * Default: reuse the {@code ClientHttpRequestFactoryBuilder} bean already present in the context,
         * as built by Spring Boot's own auto-configuration (honoring {@code spring.http.clients.*} and any
         * {@code ClientHttpRequestFactoryBuilderCustomizer} registered by the application).
         * </p>
         * <p>
         * The context builder is enriched with the spring-addons customization, which supports only
         * {@code HttpComponentsClientHttpRequestFactoryBuilder},
         * {@code JdkClientHttpRequestFactoryBuilder}, and {@code JettyClientHttpRequestFactoryBuilder};
         * for any other builder type (Reactor, Simple, an application-provided {@code of(...)}), a
         * {@link com.c4_soft.springaddons.rest.RestMisconfigurationException} is thrown.
         * </p>
         */
        FROM_CONTEXT,
        /**
         * Expose a {@link JdkClientHttpRequestFactory} bean
         */
        JDK,
        /**
         * Expose an Apache {@link HttpComponentsClientHttpRequestFactory} bean.
         * org.apache.httpcomponents.client5:httpclient5 must be on the class-path.
         */
        HTTP_COMPONENTS,
        /**
         * Expose a {@link JettyClientHttpRequestFactory} bean. org.eclipse.jetty:jetty-client must
         * be on the class-path.
         */
        JETTY
      }

    }

    public static enum ClientType {
      DEFAULT, REST_CLIENT, WEB_CLIENT;
    }
  }

  @Data
  public static class RestGroupProperties {
    /**
     * <p>
     * The client-id (key under "com.c4-soft.springaddons.rest.client") whose already
     * auto-configured {@link RestClient} or {@link WebClient} bean this group should reuse.
     * </p>
     * <p>
     * The client keeps existing as an independently injectable bean: referencing it from a group
     * does not change how it is exposed, it only makes the group's HTTP Service proxies share its
     * base URL, headers, authorization and underlying request factory / connector.
     * </p>
     * <p>
     * The group's connect-timeout, read-timeout, redirects, cookie-handling and SSL bundle still
     * fall back to {@code spring.http.serviceclient.<group-name>.*} (Spring Boot's own per-group
     * properties) when the referenced client-id leaves them unset, before falling further back to
     * {@code spring.http.clients.*}.
     * </p>
     */
    private String client;
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
