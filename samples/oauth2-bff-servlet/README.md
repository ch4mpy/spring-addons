# Servlet OAuth2 BFF
Sample for an OAuth2 BFF using the WebMvc (aka servlet or synchronized) version of Spring Cloud Gateway.

The Javascript UI is written with JQuery and included in a Thymeleaf template.

As logout (made with a POST) and PUT request are made with ajax (XHR), the CSRF protection is configured with `HttpOnly=flase` cookies.

The `webmvc-jwt-default` module can be used as _"downstream micro-service"_.