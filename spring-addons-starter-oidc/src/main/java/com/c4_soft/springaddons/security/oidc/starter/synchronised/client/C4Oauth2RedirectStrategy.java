package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * A redirect strategy that might not actually redirect: the HTTP status is taken from com.c4-soft.springaddons.oidc.client.oauth2-redirect-status property.
 * User-agents will auto redirect only if the status is in 3xx range. This gives single page and mobile applications a chance to intercept the redirection and
 * choose to follow the redirection (or not), with which agent and potentially by clearing some headers.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@RequiredArgsConstructor
public class C4Oauth2RedirectStrategy implements RedirectStrategy {
	private final HttpStatus defaultStatus;

	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String location) throws IOException {
		// @formatter:off
		final var status = Optional.ofNullable(request.getHeader("X-RESPONSE-STATUS"))
			.filter(StringUtils::hasLength)
			.map(statusStr -> {
				try {
					final var statusCode = Integer.parseInt(statusStr);
					return HttpStatus.valueOf(statusCode);
				} catch(NumberFormatException e) {
					return HttpStatus.valueOf(statusStr.toUpperCase());
				}
			})
			.orElse(defaultStatus);
		// @formatter:on
		response.setStatus(status.value());
		response.setHeader(HttpHeaders.LOCATION, location);
	}

}