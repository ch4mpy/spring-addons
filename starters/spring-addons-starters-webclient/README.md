# spring-boot starter for `C4WebClientBuilderFactoryService`
Tiny lib exposing a factory service for WebClient builders with proxy configuration from properties

## Usage
Thanks to `@AutoConfiguration` magic, only 3 very simple steps are needed:
### Put this library on your classpath
```xml
        <dependency>
            <groupId>com.c4-soft.springaddons.starter</groupId>
            <artifactId>spring-addons-starters-webclient</artifactId>
            <version>${spring-addons.version}</version>
        </dependency>
```

### Configuration
Two sources of configuration properties are evaluated:
- `com.c4-soft.springaddons.proxy.*`
- `http_proxy` and `no_proxy`

`com.c4-soft.springaddons.proxy.*` have precedence if `host` is not empty. This means that the standard `HTTP_PROXY` and `NO_PROXY` environment variables will be used only if:
- `com.c4-soft.springaddons.proxy.host` is left empty
- `com.c4-soft.springaddons.proxy.enabled` is left empty or is explicitly set to `true`

There is a noteworthy difference between the two possible properties for configuring proxy bypass:
- `com.c4-soft.springaddons.proxy.non-proxy-hosts-pattern` expects Java RegEx (for instance `(localhost)|(bravo\\-ch4mp)|(.*\\.corporate\\-domain\\.com)`)
- `no_proxy` expects comma separated list of hosts / domains (for instance `localhost,bravo-ch4mp,.env-domain.pf`)

### Inject `C4WebClientBuilderFactoryService` where you need it
```java
@RestController
@RequestMapping("/")
@RequiredArgsConstructor
public class GreetingController {
    private final C4WebClientBuilderFactoryService webClientBuilderFactory;
    ...
}
```

## Sample
You might refer to unit-tests for a sample spring-boot app:
```java
@SpringBootApplication
public class WebClientSampleApp {
    public static void main(String[] args) {
        new SpringApplicationBuilder(WebClientSampleApp.class).web(WebApplicationType.REACTIVE).run(args);
    }

    @RestController
    @RequestMapping("/sample")
    @RequiredArgsConstructor
    public static class SampleController {
        private final C4WebClientBuilderFactoryService webClientBuilderFactory;

        @GetMapping("/delegating")
        public Mono<String> calling() throws MalformedURLException {
            return webClientBuilderFactory.get(new URL("http://localhost:8080")).build().get().uri("/sample/delegate").retrieve().bodyToMono(String.class);
        }

        @GetMapping("/delegate")
        public Mono<String> remote() {
            return Mono.just("Hello!");
        }
    }
}
```
Properties file uses profiles to try various configuration scenarios:
```properties
server.port=8080
server.ssl.enabled=false

#---
spring.config.activate.on-profile=host-port
com.c4-soft.springaddons.proxy.host=mini-proxy
com.c4-soft.springaddons.proxy.port=7080

#---
spring.config.activate.on-profile=addons
com.c4-soft.springaddons.proxy.type=socks5
com.c4-soft.springaddons.proxy.host=corp-proxy
com.c4-soft.springaddons.proxy.port=8080
com.c4-soft.springaddons.proxy.username=toto
com.c4-soft.springaddons.proxy.password=abracadabra
com.c4-soft.springaddons.proxy.nonProxyHostsPattern=(localhost)|(bravo\\-ch4mp)|(.*\\.corporate\\-domain\\.com)
com.c4-soft.springaddons.proxy.connect-timeout-millis=500

#---
spring.config.activate.on-profile=disabled-proxy
com.c4-soft.springaddons.proxy.enabled=false

#---
spring.config.activate.on-profile=std-env-vars
http_proxy=https://machin:truc@env-proxy:8080
no_proxy=localhost,bravo-ch4mp,.env-domain.pf
```