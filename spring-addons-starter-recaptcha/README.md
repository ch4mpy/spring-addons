# spring-addons-starter-recaptcha

Server-side validation of Google [reCAPTCHA](https://developers.google.com/recaptcha) v2 and v3 tokens submitted by clients to a Spring Boot application.

```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-recaptcha</artifactId>
    <version>${springaddons.version}</version>
</dependency>
```

Only `secret-key` is required:

```properties
com.c4-soft.springaddons.recaptcha.secret-key=change-me
```

Inject `C4ReCaptchaValidationService` where a token has to be checked. The HTTP client used to call the `siteverify` endpoint is configured with the same properties as an auto-configured client of [`spring-addons-starter-rest`](../spring-addons-starter-rest): proxy, timeouts, SSL, implementation.

[Complete documentation](https://ch4mpy.github.io/spring-addons/recaptcha/), including the response scores, the HTTP client configuration and how to override the validation service.
