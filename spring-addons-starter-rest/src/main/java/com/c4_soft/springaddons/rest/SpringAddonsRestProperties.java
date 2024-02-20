package com.c4_soft.springaddons.rest;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;

/**
 * <p>
 * Configuration for HTTP or SOCKS proxy.
 * </p>
 * <p>
 * HTTP_PROXY and NO_PROXY standard environment variable are used only if com.c4-soft.springaddons.proxy.hostname is left empty and
 * com.c4-soft.springaddons.proxy.enabled is TRUE or null.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
@Data
@AutoConfiguration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.rest")
public class SpringAddonsRestProperties {
    private ProxyProperties proxy = new ProxyProperties();

    private Map<String, ClientProperties> client = new HashMap<>();

    @Data
    @ConfigurationProperties
    public static class ProxyProperties {
        private boolean enabled = true;
        private String protocol = "http";
        private int port = 8080;
        private String username;
        private String password;
        private int connectTimeoutMillis = 10000;

        @Getter(AccessLevel.NONE)
        private Optional<String> host = Optional.empty();

        @Getter(AccessLevel.NONE)
        private String nonProxyHostsPattern;

        /* also parse standard environment variables */
        @Getter(AccessLevel.NONE)
        private Optional<URL> httpProxy = Optional.empty();

        @Getter(AccessLevel.NONE)
        @Value("${no_proxy:#{T(java.util.List).of()}}")
        private List<String> noProxy = List.of();

        @Value("${com.c4-soft.springaddons.proxy.host:#{null}}")
        public void setHost(String host) {
            this.host = StringUtils.hasText(host) ? Optional.of(host) : Optional.empty();
        }

        @Value("${http_proxy:#{null}}")
        public void setHttpProxy(String url) throws MalformedURLException {
            this.httpProxy = StringUtils.hasText(url) ? Optional.of(new URL(url)) : Optional.empty();
        }

        public boolean isEnabled() {
            return enabled && getHostname().isPresent();
        }

        public Optional<String> getHostname() {
            if (!enabled) {
                return Optional.empty();
            }
            return host.isPresent() ? host : httpProxy.map(URL::getHost);
        }

        public String getProtocol() {
            if (!enabled) {
                return null;
            }
            return host.map(h -> protocol).orElse(httpProxy.map(URL::getProtocol).orElse(null));
        }

        public int getPort() {
            return host.map(h -> port).orElse(httpProxy.map(URL::getPort).orElse(port));
        }

        public String getUsername() {
            if (!enabled) {
                return null;
            }
            return host.map(h -> username).orElse(httpProxy.map(URL::getUserInfo).map(ProxyProperties::getUserinfoName).orElse(null));
        }

        public String getPassword() {
            if (!enabled) {
                return null;
            }
            return host.map(h -> password).orElse(httpProxy.map(URL::getUserInfo).map(ProxyProperties::getUserinfoPassword).orElse(null));
        }

        public String getNoProxy() {
            if (!enabled) {
                return null;
            }
            return Optional.ofNullable(nonProxyHostsPattern).filter(StringUtils::hasText).orElse(getNonProxyHostsPattern(noProxy));
        }

        static String getUserinfoName(String userinfo) {
            if (userinfo == null) {
                return null;
            }
            return userinfo.split(":")[0];
        }

        static String getUserinfoPassword(String userinfo) {
            if (userinfo == null) {
                return null;
            }
            final var splits = userinfo.split(":");
            return splits.length < 2 ? null : splits[1];
        }

        static String getNonProxyHostsPattern(List<String> noProxy) {
            if (noProxy == null || noProxy.isEmpty()) {
                return null;
            }
            return noProxy
                .stream()
                .map(host -> host.replace(".", "\\."))
                .map(host -> host.replace("-", "\\-"))
                .map(host -> host.startsWith("\\.") ? ".*" + host : host)
                .collect(Collectors.joining(")|(", "(", ")"));
        }
    }

    @Data
    @ConfigurationProperties
    public static class ClientProperties {
        /**
         * Base URI used to build the REST client ({@link RestClient} or {@link WebClient})
         */
        private Optional<URL> baseUrl = Optional.empty();

        private AuthorizationProperties authorization = new AuthorizationProperties();

        @Data
        @ConfigurationProperties
        public static class AuthorizationProperties {

            private OAuth2Properties oauth2 = new OAuth2Properties();

            private BasicAuthProperties basic = new BasicAuthProperties();

            boolean isConfigured() {
                return oauth2.isConfigured() || basic.isConfigured();
            }

            boolean isConfValid() {
                return oauth2.isConfValid() && basic.isConfValid() && (!oauth2.isConfigured() || !basic.isConfigured());
            }

            @Data
            @ConfigurationProperties
            public static class OAuth2Properties {
                /**
                 * <p>
                 * If provided, it is used to get an access token from the {@link OAuth2AuthorizedClientManager}.
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
                 * If true, a {@link BearerProvider} is used to retrieve a Bearer token from the {@link Authentication} in the security context.
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
