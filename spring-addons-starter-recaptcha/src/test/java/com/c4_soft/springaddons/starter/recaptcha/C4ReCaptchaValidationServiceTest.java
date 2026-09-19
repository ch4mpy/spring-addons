package com.c4_soft.springaddons.starter.recaptcha;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import java.net.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class C4ReCaptchaValidationServiceTest {
  private static final String SITEVERIFY = "https://localhost/recaptcha/api/siteverify";

  MockRestServiceServer server;
  C4ReCaptchaValidationService service;

  @BeforeEach
  void setUp() {
    final var settings = new C4ReCaptchaSettings();
    settings.setSecretKey("s3cret");
    settings.setSiteverifyUrl(URI.create(SITEVERIFY));
    settings.setV3Threshold(.8);
    final var builder = RestClient.builder();
    server = MockRestServiceServer.bindTo(builder).build();
    service = new C4ReCaptchaValidationService(settings, builder.baseUrl(SITEVERIFY).build());
  }

  @Test
  void givenValidToken_whenCheckV2_thenTrueAndSecretIsSentAsForm() {
    server.expect(requestTo(SITEVERIFY)).andExpect(method(HttpMethod.POST))
        .andExpect(content().contentType(MediaType.APPLICATION_FORM_URLENCODED))
        .andExpect(content().formData(form("s3cret", "token")))
        .andRespond(withSuccess("{\"success\":true,\"challenge_ts\":\"2026-09-19T10:00:00Z\",\"hostname\":\"localhost\"}",
            MediaType.APPLICATION_JSON));

    assertThat(service.checkV2("token")).isTrue();
    server.verify();
  }

  @Test
  void givenInvalidToken_whenCheckV2_thenFalse() {
    server.expect(requestTo(SITEVERIFY)).andRespond(withSuccess(
        "{\"success\":false,\"error-codes\":[\"invalid-input-response\"]}",
        MediaType.APPLICATION_JSON));

    assertThat(service.checkV2("token")).isFalse();
  }

  @Test
  void givenScoreAboveThreshold_whenCheckV3_thenScore() {
    server.expect(requestTo(SITEVERIFY)).andRespond(withSuccess(
        "{\"success\":true,\"score\":0.9,\"action\":\"login\",\"challenge_ts\":\"2026-09-19T10:00:00Z\",\"hostname\":\"localhost\"}",
        MediaType.APPLICATION_JSON));

    assertThat(service.checkV3("token", "login")).isEqualTo(.9);
  }

  @Test
  void givenScoreBelowThreshold_whenCheckV3_thenValidationException() {
    server.expect(requestTo(SITEVERIFY)).andRespond(withSuccess(
        "{\"success\":true,\"score\":0.3,\"action\":\"login\"}", MediaType.APPLICATION_JSON));

    assertThatThrownBy(() -> service.checkV3("token"))
        .isInstanceOf(ReCaptchaValidationException.class).hasMessageContaining("0.3")
        .hasMessageContaining("0.8");
  }

  @Test
  void givenInvalidToken_whenCheckV3_thenValidationExceptionWithErrorCodes() {
    server.expect(requestTo(SITEVERIFY)).andRespond(withSuccess(
        "{\"success\":false,\"error-codes\":[\"invalid-input-response\",\"timeout-or-duplicate\"]}",
        MediaType.APPLICATION_JSON));

    assertThatThrownBy(() -> service.checkV3("user-submitted-value"))
        .isInstanceOf(ReCaptchaValidationException.class)
        .hasMessageContaining("invalid-input-response").hasMessageContaining("timeout-or-duplicate")
        // the submitted value itself is not echoed in the message
        .satisfies(e -> assertThat(e.getMessage()).doesNotContain("user-submitted-value"));
  }

  @Test
  void givenTokenForAnotherAction_whenCheckV3WithExpectedAction_thenValidationException() {
    server.expect(requestTo(SITEVERIFY)).andRespond(withSuccess(
        "{\"success\":true,\"score\":0.9,\"action\":\"signup\"}", MediaType.APPLICATION_JSON));

    assertThatThrownBy(() -> service.checkV3("token", "login"))
        .isInstanceOf(ReCaptchaValidationException.class).hasMessageContaining("signup")
        .hasMessageContaining("login");
  }

  @Test
  void givenNoExpectedAction_whenCheckV3_thenActionIsNotChecked() {
    server.expect(requestTo(SITEVERIFY)).andRespond(withSuccess(
        "{\"success\":true,\"score\":0.9,\"action\":\"signup\"}", MediaType.APPLICATION_JSON));

    assertThat(service.checkV3("token")).isEqualTo(.9);
  }

  private static org.springframework.util.MultiValueMap<String, String> form(String secret,
      String response) {
    final var form = new org.springframework.util.LinkedMultiValueMap<String, String>();
    form.add("secret", secret);
    form.add("response", response);
    return form;
  }
}
