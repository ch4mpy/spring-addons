package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static org.assertj.core.api.Assertions.assertThat;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

class SpringAddonsOauth2RedirectStrategyTest {
  private final SpringAddonsOauth2RedirectStrategy strategy =
      new SpringAddonsOauth2RedirectStrategy(HttpStatus.FOUND);

  @Test
  void givenNoStatusHeaderNorParam_whenSendRedirect_thenDefaultStatus() throws IOException {
    final var response = sendRedirect(new MockHttpServletRequest());

    assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
    assertThat(response.getHeader(HttpHeaders.LOCATION)).isEqualTo("/ui");
  }

  @Test
  void givenStatusHeader_whenSendRedirect_thenHeaderStatus() throws IOException {
    final var request = new MockHttpServletRequest();
    request.addHeader(SpringAddonsOidcClientProperties.RESPONSE_STATUS_HEADER, "202");

    assertThat(sendRedirect(request).getStatus()).isEqualTo(HttpStatus.ACCEPTED.value());
  }

  @Test
  void givenStatusNameParam_whenSendRedirect_thenParamStatus() throws IOException {
    final var request = new MockHttpServletRequest();
    request.setParameter(SpringAddonsOidcClientProperties.RESPONSE_STATUS_PARAM, "accepted");

    assertThat(sendRedirect(request).getStatus()).isEqualTo(HttpStatus.ACCEPTED.value());
  }

  @Test
  void givenMalformedStatusHeaderAndParam_whenSendRedirect_thenDefaultStatus()
      throws IOException {
    final var request = new MockHttpServletRequest();
    request.addHeader(SpringAddonsOidcClientProperties.RESPONSE_STATUS_HEADER, "not-a-status");
    request.setParameter(SpringAddonsOidcClientProperties.RESPONSE_STATUS_PARAM, "999");

    assertThat(sendRedirect(request).getStatus()).isEqualTo(HttpStatus.FOUND.value());
  }

  private MockHttpServletResponse sendRedirect(MockHttpServletRequest request)
      throws IOException {
    final var response = new MockHttpServletResponse();
    strategy.sendRedirect(request, response, "/ui");
    return response;
  }
}
