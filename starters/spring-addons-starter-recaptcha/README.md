# spring-boot starter for Google reCAPTCHA validation
Tiny lib to verify Google reCAPTCHA submitted by clients to spring-boot apps.

## Usage
Thanks to `@AutoConfiguration` magic, only 3 very simple steps are needed:
1. Put this library on your classpath
```xml
		<dependency>
			<groupId>com.c4-soft.springaddons.starter</groupId>
			<artifactId>spring-addons-starter-recaptcha</artifactId>
			<version>${spring-addons.version}</version>
		</dependency>
```
2. Declare a few properties (`secret-key` value is to be retrieved from https://www.google.com/recaptcha/admin/site)
```properties
com.c4-soft.springaddons.recaptcha.secret-key=machin
com.c4-soft.springaddons.recaptcha.siteverify-url=https://localhost/recaptcha/api/siteverify
com.c4-soft.springaddons.recaptcha.v3-threshold=0.8
```
3. Inject `ReCaptchaValidationService` where you need it
```java
@RestController
@RequestMapping("/greet")
@RequiredArgsConstructor
public class GreetingController {
	private final ReCaptchaValidationService captcha;

	@GetMapping("/{who}")
	public Mono<String> greet(@PathVariable("who") String who, @RequestParam("reCaptcha") String reCaptcha) {
		return captcha.checkV2(reCaptcha).map(isHuman -> Boolean.TRUE.equals(isHuman) ? String.format("Hi %s", who) : "Hello Mr. Robot");
	}
}
```

## Proxy configuration

This library depends on `spring-addons-starter-webclient` to issue HTTP requests to validation server. As so, you can configure proxy settings from properties:
```properties
com.c4-soft.springaddons.proxy.hostname=http://localhost
com.c4-soft.springaddons.proxy.port=8080
# More from IDE auto-completion
```
