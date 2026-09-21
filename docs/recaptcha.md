---
title: spring-addons-starter-recaptcha
nav_order: 11
description: "Server-side validation of Google reCAPTCHA v2 and v3 tokens from a Spring Boot application, with the HTTP client configured from properties."
---

# `spring-addons-starter-recaptcha`


Server-side validation of Google [reCAPTCHA](https://developers.google.com/recaptcha) v2 and v3 tokens submitted by clients to a Spring Boot application.

## Usage

### Dependency
```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-recaptcha</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
```

### Properties
Only `secret-key` is required (from https://www.google.com/recaptcha/admin/site):
```properties
com.c4-soft.springaddons.recaptcha.secret-key=change-me
# defaults:
com.c4-soft.springaddons.recaptcha.siteverify-url=https://www.google.com/recaptcha/api/siteverify
com.c4-soft.springaddons.recaptcha.v3-threshold=0.5
```
The application fails to start with an explicit message if `secret-key` is missing.

### Inject `C4ReCaptchaValidationService`
```java
@RestController
@RequiredArgsConstructor
public class GreetingController {
    private final C4ReCaptchaValidationService captcha;

    // reCAPTCHA v2: the token is either valid or not
    @GetMapping("/greet/{who}")
    public String greet(@PathVariable String who, @RequestParam("reCaptcha") String reCaptcha) {
        return captcha.checkV2(reCaptcha) ? "Hi %s".formatted(who) : "Hello Mr. Robot";
    }

    // reCAPTCHA v3: throws ReCaptchaValidationException if the token is invalid, was generated
    // for another action, or if its score is below v3-threshold
    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@RequestBody SignupDto dto, @RequestHeader("X-ReCaptcha") String reCaptcha) {
        captcha.checkV3(reCaptcha, "signup");
        ...
    }
}
```
`checkV3(token)` (without expected action) skips the action check. Google [recommends](https://developers.google.com/recaptcha/docs/v3#interpreting_the_score) verifying it: otherwise a token obtained for any action of your site is accepted.

## HTTP client configuration

Requests to the siteverify endpoint are sent with a `RestClient` built from the application's auto-configured `RestClient.Builder` (so the application's message converters and observation apply) and a request factory configured with `com.c4-soft.springaddons.recaptcha.http.*`: the same properties as `com.c4-soft.springaddons.rest.client.<id>.http.*` from [spring-addons-starter-rest]({{ site.baseurl }}/rest/request-factories/) (proxy, timeouts, SSL, implementation…):
```properties
com.c4-soft.springaddons.recaptcha.http.proxy.host=corp-proxy
com.c4-soft.springaddons.recaptcha.http.proxy.port=3128
com.c4-soft.springaddons.recaptcha.http.connect-timeout-millis=2000
com.c4-soft.springaddons.recaptcha.http.read-timeout-millis=2000
```
Without explicit proxy properties, the `http_proxy` / `no_proxy` environment variables are honored.

## Overriding
`C4ReCaptchaValidationService` is `@ConditionalOnMissingBean`: expose your own bean to replace the auto-configured one, for instance with a `RestClient` of your own:
```java
@Bean
C4ReCaptchaValidationService reCaptcha(C4ReCaptchaSettings settings, RestClient.Builder builder) {
    return new C4ReCaptchaValidationService(settings, builder.baseUrl(settings.getSiteverifyUrl().toString()).build());
}
```
