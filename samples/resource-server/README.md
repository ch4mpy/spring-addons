# `resource-server`: a servlet REST API secured with JWT access tokens

**What it shows**: `spring-addons-starter-oidc` replacing the `SecurityFilterChain`, `JwtDecoder`, authorities converter, CORS and access-control Java configuration of an OAuth2 resource server with a few properties, and `spring-addons-starter-oidc-test` populating the test security context with annotations (on a `@Service` as well as in `@WebMvcTest`).

Port: `8081`. Reactive counterpart: [`../resource-server-reactive`](../resource-server-reactive).

## What you'd write without spring-addons

With `spring-boot-starter-security-oauth2-resource-server` alone, accepting tokens from Keycloak with roles mapped from `realm_access.roles`, `preferred_username` as name, anonymous access to a public route, CORS for a SPA and `401` (not a login redirect) for unauthorized requests is a `SecurityFilterChain` bean with `sessionManagement`, `csrf`, `cors` (and a `CorsConfigurationSource`), `authorizeHttpRequests`, `exceptionHandling`, and `oauth2ResourceServer` configured with a `JwtAuthenticationConverter` holding a custom `JwtGrantedAuthoritiesConverter`. Add a second issuer and you also need a `JwtIssuerAuthenticationManagerResolver` with one `JwtDecoder` and one converter per issuer.

## What this sample contains instead

[`application.yml`](src/main/resources/application.yml):
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
          - iss: ${keycloak-issuer}
            username-claim: preferred_username
            authorities:
              - path: $.realm_access.roles
              - path: $.resource_access.*.roles
          - iss: https://dev-ch4mpy.eu.auth0.com/
            username-claim: $['https://c4-soft.com/user']['name']
            authorities:
              - path: $['https://c4-soft.com/user']['roles']
              - path: $.permissions
                prefix: PERMISSION_
                caze: upper
        resourceserver:
          permit-all:
            - /greetings/public
        cors:
          - path: /**
            allowed-origin-patterns: ${allowed-origins}
```
- `ops`: one entry per trusted issuer. The `iss` claim of a token selects the entry, which holds the JWT decoder configuration (built lazily, so an unreachable issuer doesn't break startup) and how to derive the `Authentication` name and authorities from the claims (JSON paths, optional prefix and case).
- `resourceserver.permit-all`: everything else requires a valid token. The chain is stateless, CSRF is disabled, and unauthorized requests get a `401` with a `WWW-Authenticate` header.
- `cors`: a global CORS filter; pre-flight requests to these paths are allowed anonymously.

[`SecurityConfig`](src/main/java/com/c4_soft/springaddons/samples/resourceserver/SecurityConfig.java) is the only security Java code: `@EnableMethodSecurity` and a single `JwtAbstractAuthenticationTokenConverter` bean which switches the `Authentication` implementation to `OAuthentication<OpenidToken>` (typed accessors to OpenID claims). Almost every bean of the starter is `@ConditionalOnMissingBean`: replace the one you need, keep the rest. Delete this bean to get Spring's `JwtAuthenticationToken`.

Endpoints ([`GreetingsController`](src/main/java/com/c4_soft/springaddons/samples/resourceserver/greetings/GreetingsController.java), [`GreetingsService`](src/main/java/com/c4_soft/springaddons/samples/resourceserver/greetings/GreetingsService.java)):

| Route | Access | Where the rule lives |
|---|---|---|
| `GET /greetings/public` | anonymous | `permit-all` property |
| `GET /greetings/me` | authenticated | `@PreAuthorize` on the controller and the service |
| `GET /greetings/nice` | `NICE` authority | `@PreAuthorize` on the `@Service` |

Access control from Java configuration is possible too: expose a `ResourceServerExpressionInterceptUrlRegistryPostProcessor` bean (it is applied after `permit-all`).

## Tests

Claim-sets for the two users of the Keycloak realm are dumped in [`src/test/resources`](src/test/resources) (`brice.json` has the `NICE` realm role, `igor.json` doesn't). Tokens are never decoded in tests: the `Authentication` is built from these files by the **application's** converter bean, so name, authorities and type are what they'd be at runtime.

- [`GreetingsControllerTest`](src/test/java/com/c4_soft/springaddons/samples/resourceserver/greetings/GreetingsControllerTest.java): `@WebMvcTest` + `@AutoConfigureAddonsWebmvcResourceServerSecurity` (imports the starter's auto-configuration in the slice), `MockMvcSupport` shortcuts, `@WithJwt("brice.json")`, `@WithAnonymousUser`, and a `@ParameterizedTest` fed by `WithJwt.AuthenticationFactory`.
- [`GreetingsServiceTest`](src/test/java/com/c4_soft/springaddons/samples/resourceserver/greetings/GreetingsServiceTest.java): `@PreAuthorize` on a `@Service`, tested by calling the bean directly (no `MockMvc`), with `@AddonsWebmvcComponentTest`.
- [`ResourceServerApplicationTest`](src/test/java/com/c4_soft/springaddons/samples/resourceserver/ResourceServerApplicationTest.java): full context with `AddonsWebmvcTestConf` (mocks the JWT decoding), including CORS pre-flight checks.

`@WithMockAuthentication` (name and authorities inline, no claims) is demonstrated in the reactive sample: it mocks the `Authentication`, which works with Spring's `JwtAuthenticationToken` but not with `OAuthentication` (see the samples README).

## The `introspection` profile

Run with `--spring.profiles.active=introspection` and the same application validates access tokens by calling the authorization server's introspection endpoint instead of decoding them locally:

```bash
../../mvnw -f pom.xml spring-boot:run -Dspring-boot.run.profiles=introspection
```

[`application-introspection.yml`](src/main/resources/application-introspection.yml) only adds the standard Spring Boot `opaquetoken` properties. Setting `introspection-uri` is what makes the starter build an introspecting filter chain rather than a JWT decoder one; the authorities and the username still come from the same `com.c4-soft.springaddons.oidc.ops` entry, because an introspection response is a claim-set mapped exactly like a JWT payload.

The default `Authentication` of an introspecting chain would be a `BearerTokenAuthentication`, so [`IntrospectionSecurityConfig`](src/main/java/com/c4_soft/springaddons/samples/resourceserver/IntrospectionSecurityConfig.java) exposes an `OpaqueTokenAuthenticationConverter` producing the same `OAuthentication<OpenidToken>` as the JWT one. **Controllers, services and their tests are unchanged.** [`IntrospectionProfileTest`](src/test/java/com/c4_soft/springaddons/samples/resourceserver/IntrospectionProfileTest.java) asserts exactly that, with `@WithOpaqueToken` in place of `@WithJwt` (same claim-set files, run through the opaque token converter).

Mind that introspection means one call to the authorization server for **every** request the API processes: latency on each request, and load on the OP. Prefer a JWT decoder unless immediate revocation, or tokens which are opaque by design, really require it.

## Run it

```bash
docker compose -f ../../infra/compose.yml up -d   # Keycloak on http://localhost:7080
../../mvnw -f pom.xml spring-boot:run
curl http://localhost:8081/greetings/public
curl -i http://localhost:8081/greetings/me        # 401
```
To call `/greetings/me` you need a Bearer access token from the `spring-addons` realm: log in through the [`bff`](../bff) sample (`http://localhost:8080/bff/api/greetings/me` after `http://localhost:8080/oauth2/authorization/spring-addons-user`), or run the `client_credentials` flow with the `spring-addons-m2m` client (`secret`) as the [`rest-client`](../rest-client) sample does:
```bash
TOKEN=$(curl -s -d client_id=spring-addons-m2m -d client_secret=secret -d grant_type=client_credentials \
  http://localhost:7080/auth/realms/spring-addons/protocol/openid-connect/token | sed 's/.*"access_token":"\([^"]*\)".*/\1/')
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/greetings/me
```
