package com.c4_soft.springaddons.rest.synchronised;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.web.client.RestClient;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties;

class RestClientBuilderFactoryBeanAuthorizationTest {

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void givenBasicAuthWithEncodedCredentials_whenRequest_thenAuthorizationHeaderIsSet()
      throws Exception {
    final var clientProperties = new RestClientProperties();
    clientProperties.getAuthorization().getBasic().setEncodedCredentials(Optional.of("dXNlcjpwd2Q="));

    final var headers = send(clientProperties);

    assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Basic dXNlcjpwd2Q=");
  }

  @Test
  void givenBasicAuthWithUsernameAndPassword_whenRequest_thenAuthorizationHeaderIsSet()
      throws Exception {
    final var clientProperties = new RestClientProperties();
    clientProperties.getAuthorization().getBasic().setUsername(Optional.of("user"));
    clientProperties.getAuthorization().getBasic().setPassword(Optional.of("pwd"));

    final var headers = send(clientProperties);

    assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Basic dXNlcjpwd2Q=");
  }

  @Test
  void givenBasicAuthWithUsernamePasswordAndCharset_whenRequest_thenAuthorizationHeaderIsSet()
      throws Exception {
    final var clientProperties = new RestClientProperties();
    clientProperties.getAuthorization().getBasic().setUsername(Optional.of("user"));
    clientProperties.getAuthorization().getBasic().setPassword(Optional.of("pwd"));
    clientProperties.getAuthorization().getBasic().setCharset(Optional.of(StandardCharsets.UTF_8));

    final var headers = send(clientProperties);

    assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Basic dXNlcjpwd2Q=");
  }

  @Test
  void givenBasicAuthWithEncodedCredentialsAndUsername_whenGetObject_thenMisconfiguration() {
    final var clientProperties = new RestClientProperties();
    clientProperties.getAuthorization().getBasic().setEncodedCredentials(Optional.of("dXNlcjpwd2Q="));
    clientProperties.getAuthorization().getBasic().setUsername(Optional.of("user"));

    assertThatThrownBy(() -> factoryBean(clientProperties).getObject())
        .isInstanceOf(RestMisconfigurationException.class);
  }

  @Test
  void givenBasicAuthWithUsernameOnly_whenGetObject_thenMisconfiguration() {
    final var clientProperties = new RestClientProperties();
    clientProperties.getAuthorization().getBasic().setUsername(Optional.of("user"));

    assertThatThrownBy(() -> factoryBean(clientProperties).getObject())
        .isInstanceOf(RestMisconfigurationException.class);
  }

  @Test
  void givenForwardBearerAndIntrospectedAuthentication_whenRequest_thenBearerIsForwarded()
      throws Exception {
    final var clientProperties = new RestClientProperties();
    clientProperties.getAuthorization().getOauth2().setForwardBearer(true);
    final var principal = new OAuth2IntrospectionAuthenticatedPrincipal(
        Map.of("sub", "ch4mp", "active", true), List.of(new SimpleGrantedAuthority("NICE")));
    final var accessToken = new OAuth2AccessToken(TokenType.BEARER, "opaque-token",
        Instant.now(), Instant.now().plusSeconds(60));
    setAuthentication(new BearerTokenAuthentication(principal, accessToken, List.of()));

    final var headers = send(clientProperties);

    assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer opaque-token");
  }

  @Test
  void givenForwardBearerAndAnonymous_whenRequest_thenNoAuthorizationHeader() throws Exception {
    final var clientProperties = new RestClientProperties();
    clientProperties.getAuthorization().getOauth2().setForwardBearer(true);

    final var headers = send(clientProperties);

    assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).isNull();
  }

  static HttpHeaders send(RestClientProperties clientProperties) throws Exception {
    final var sent = new AtomicReference<MockClientHttpRequest>();
    final ClientHttpRequestFactory recordingFactory = (uri, method) -> {
      final var request = new MockClientHttpRequest(method, uri);
      request.setResponse(new MockClientHttpResponse(new byte[0], HttpStatus.NO_CONTENT));
      sent.set(request);
      return request;
    };
    final RestClient.Builder builder = factoryBean(clientProperties).getObject();
    builder.requestFactory(recordingFactory).build().method(HttpMethod.GET)
        .uri(URI.create("http://localhost/x")).retrieve().toBodilessEntity();
    return sent.get().getHeaders();
  }

  static RestClientBuilderFactoryBean factoryBean(RestClientProperties clientProperties) {
    final var restProperties = new SpringAddonsRestProperties();
    restProperties.getClient().put("test-client", clientProperties);
    final var factoryBean = new RestClientBuilderFactoryBean();
    factoryBean.setClientId("test-client");
    factoryBean.setRestProperties(restProperties);
    factoryBean.setAuthorizedClientManager(Optional.empty());
    factoryBean.setClientRegistrationRepository(Optional.empty());
    factoryBean.setClientHttpRequestFactory(Optional.empty());
    factoryBean.setClientHttpRequestFactoryBuilder(Optional.empty());
    factoryBean.setHttpClientSettings(Optional.empty());
    return factoryBean;
  }

  static void setAuthentication(Authentication authentication) {
    SecurityContextHolder.setContext(new SecurityContextImpl(authentication));
  }
}
