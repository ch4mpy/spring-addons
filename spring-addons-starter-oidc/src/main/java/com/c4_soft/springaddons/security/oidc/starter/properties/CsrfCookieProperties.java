package com.c4_soft.springaddons.security.oidc.starter.properties;

import lombok.Data;
import org.springframework.boot.web.server.Cookie;

import java.util.Optional;

@Data
public class CsrfCookieProperties {
    /**
     * The default value is well supported by Angular and React, but may cause collisions when several
     * applications are hosted on the same backend.
     */
    private String name = "XSRF-TOKEN";

    /**
     * Might be changed to prevent collisions when several applications are hosted on the same backend.
     * Be aware that the CSRF cookie path must be shared by the front end and REST API. For example, the
     * path can be set to "/foo" with UI assets available from "/foo/ui/**" and REST resources
     * from "/foo/bff/v1/**"
     */
    private String path = "/";

    /**
     * Optional customization of the SameSite cookie attribute. Default is "OMITTED".
     */
    private Cookie.SameSite sameSite = Cookie.SameSite.OMITTED;

    /**
     * Optional customization of the Domain cookie attribute.
     */
    private Optional<String> domain = Optional.empty();
}
