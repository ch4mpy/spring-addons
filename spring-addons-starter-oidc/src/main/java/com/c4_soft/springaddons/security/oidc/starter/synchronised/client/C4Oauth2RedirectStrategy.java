package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.RedirectStrategy;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * @deprecated replaced by {@link SpringAddonsOauth2RedirectStrategy}
 */
@RequiredArgsConstructor
@Deprecated(forRemoval = true)
public class C4Oauth2RedirectStrategy implements RedirectStrategy {
    public static final String RESPONSE_STATUS_HEADER = "X-RESPONSE-STATUS";
    public static final String RESPONSE_LOCATION_HEADER = "X-RESPONSE-LOCATION";

    private final HttpStatus defaultStatus;

    @Override
    public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) throws IOException {
        final var requestedStatus = request.getIntHeader(RESPONSE_STATUS_HEADER);
        response.setStatus(requestedStatus > -1 ? requestedStatus : defaultStatus.value());

        final var location = Optional.ofNullable(request.getHeader(RESPONSE_LOCATION_HEADER)).orElse(url);
        response.setHeader(HttpHeaders.LOCATION, location);
    }

}
