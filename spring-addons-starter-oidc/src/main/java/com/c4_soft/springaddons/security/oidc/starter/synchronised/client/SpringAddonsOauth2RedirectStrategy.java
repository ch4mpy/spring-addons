package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.RedirectStrategy;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * A redirect strategy that might not actually redirect: the HTTP status is taken from
 * com.c4-soft.springaddons.oidc.client.oauth2-redirect-status property. User-agents will auto redirect only if the status is in 3xx range.
 * This gives single page and mobile applications a chance to intercept the redirection and choose to follow the redirection (or not), with
 * which agent and potentially by clearing some headers.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@RequiredArgsConstructor
public class SpringAddonsOauth2RedirectStrategy implements RedirectStrategy {

	@Getter
	private final HttpStatus defaultStatus;

	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String location) throws IOException {
		final var requestedStatus = request.getIntHeader(SpringAddonsOidcClientProperties.RESPONSE_STATUS_HEADER);
		response.setStatus(requestedStatus > -1 ? requestedStatus : defaultStatus.value());

		response.setHeader(HttpHeaders.LOCATION, location);
	}
}
