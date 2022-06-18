# spring-boot starter for `C4WebClientBuilderFactoryService`
Tiny lib exposing a factory service for WebClient builders with proxy configuration from properties

## Usage
Thanks to `@AutoConfiguration` magic, only 3 very simple steps are needed:
1. Put this library on your classpath
```xml
		<dependency>
			<groupId>com.c4-soft.springaddons.starter</groupId>
			<artifactId>spring-addons-starter-webclient</artifactId>
			<version>${spring-addons.version}</version>
		</dependency>
```
2. Declare a few properties 
```properties
com.c4-soft.springaddons.proxy.hostname=http://localhost
com.c4-soft.springaddons.proxy.port=8080
# More from IDE auto-completion
```
3. Inject `C4WebClientBuilderFactoryService` where you need it
```java
@RestController
@RequestMapping("/")
@RequiredArgsConstructor
public class GreetingController {
	private final C4WebClientBuilderFactoryService webClientBuilderFactory;
	...
}
```