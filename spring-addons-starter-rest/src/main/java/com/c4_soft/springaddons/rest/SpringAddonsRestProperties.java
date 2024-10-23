package com.c4_soft.springaddons.rest;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;
import lombok.Data;

/**
 * <p>
 * Configuration for HTTP or SOCKS proxy.
 * </p>
 * <p>
 * HTTP_PROXY and NO_PROXY standard environment variable are used only if
 * com.c4-soft.springaddons.rest.proxy.hostname is left empty and
 * com.c4-soft.springaddons.rest.proxy.enabled is TRUE or null.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
@Data
@AutoConfiguration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.rest")
public class SpringAddonsRestProperties {
  private ProxyProperties proxy = new ProxyProperties();

  private Map<String, RestClientProperties> client = new HashMap<>();

  @Data
  @ConfigurationProperties
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
  @ConfigurationProperties
  public static class RestClientProperties {
    /**
     * Base URI used to build the REST client ({@link RestClient} or {@link WebClient})
     */
    private Optional<String> baseUrl = Optional.empty();

    private AuthorizationProperties authorization = new AuthorizationProperties();

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
    @ConfigurationProperties
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
      @ConfigurationProperties
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
         * If true, a {@link BearerProvider} is used to retrieve a Bearer token from the
         * {@link Authentication} in the security context.
         * </p>
         * <p>
         * Mutually exclusive with auth2-registration-id property.
         * </p>
         *
         * @see DefaultBearerProvider
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
      @ConfigurationProperties
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
  }
}
