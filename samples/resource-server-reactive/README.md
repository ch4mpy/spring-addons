# `resource-server-reactive`: the WebFlux twin of `resource-server`

**What it shows**: `spring-addons-starter-oidc` and `spring-addons-starter-oidc-test` work the same in a reactive application. Same endpoints, same `application.yml` (port `8082`), same claim-set files, same test annotations; only the Spring types change:

| | [`resource-server`](../resource-server) (servlet) | `resource-server-reactive` (WebFlux) |
|---|---|---|
| Web starter | `spring-boot-starter-webmvc` | `spring-boot-starter-webflux` |
| Auto-configured chain | `SecurityFilterChain` | `SecurityWebFilterChain` |
| Method security | `@EnableMethodSecurity` | `@EnableReactiveMethodSecurity` |
| `Authentication` | `OAuthentication<OpenidToken>` (one converter bean) | Spring's default `JwtAuthenticationToken` (no bean at all) |
| Controller slice | `@WebMvcTest` + `@AutoConfigureAddonsWebmvcResourceServerSecurity` + `MockMvcSupport` | `@WebFluxTest` + `@AutoConfigureAddonsWebfluxResourceServerSecurity` + `WebTestClientSupport` |
| Component test | `@AddonsWebmvcComponentTest` | `@AddonsWebfluxComponentTest` |
| Full context | `AddonsWebmvcTestConf` | `AddonsWebfluxTestConf` |

There is no security Java configuration at all in this module: [`ResourceServerReactiveApplication`](src/main/java/com/c4_soft/springaddons/samples/resourceserver/ResourceServerReactiveApplication.java) only carries `@EnableReactiveMethodSecurity`. The username (`preferred_username`) and the authorities (`realm_access.roles`) of the `JwtAuthenticationToken` are still those configured in `com.c4-soft.springaddons.oidc.ops` for the token issuer.

## Tests

[`GreetingsControllerTest`](src/test/java/com/c4_soft/springaddons/samples/resourceserver/greetings/GreetingsControllerTest.java) also demonstrates `@WithMockAuthentication`: a Mockito mock of the `Authentication` with just a name and authorities, with no claim-set file. It is enough when the tested code only needs RBAC (here, requests denied before any claim is read); when the code reads claims, `@WithJwt` builds a real `Authentication` from a JSON file with the application's converter.

[`GreetingsServiceTest`](src/test/java/com/c4_soft/springaddons/samples/resourceserver/greetings/GreetingsServiceTest.java) checks `@PreAuthorize` on a `@Service` returning `Mono` with `StepVerifier`: the security context set by the annotations is propagated to the Reactor context.

## Run it

```bash
docker compose -f ../../infra/compose.yml up -d
../../mvnw -f pom.xml spring-boot:run
curl http://localhost:8082/greetings/public
```
See the [`resource-server` README](../resource-server/README.md#run-it) to get an access token.
