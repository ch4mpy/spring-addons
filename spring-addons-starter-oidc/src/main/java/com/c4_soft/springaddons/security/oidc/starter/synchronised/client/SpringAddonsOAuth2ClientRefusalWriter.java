package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * Default {@link OAuth2ClientRefusalWriter}: the status of the refusal, no body, no
 * {@code Location}.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Slf4j
public class SpringAddonsOAuth2ClientRefusalWriter implements OAuth2ClientRefusalWriter {

  @Override
  public void write(HttpServletRequest request, HttpServletResponse response,
      OAuth2ClientRefusal refusal) throws IOException {
    log.debug("{} on {}: answering {} ({})", refusal.kind(), request.getRequestURI(),
        refusal.status().value(), refusal.cause().getMessage());
    response.setStatus(refusal.status().value());
    response.flushBuffer();
  }
}
