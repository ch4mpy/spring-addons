# Implementing the **B**ackend **F**or **F**rontend pattern

## 1. Overview
In this tuturial, we will implement a complete system according to the **B**ackend **F**or **F**rontend pattern.

This will include a rich client running in a browser, spring-cloud-gateway as BFF and a resource-server.

Use-case will be illustrated with:
- `spring-cloud-gateway` as BFF
- Spring with `spring-boot-starter-oauth2-resource-server` for resource-server
- Angular as browser application framework
- Keycloak as authorization-server

You could easily switch to any other browser framework or OIDC authorization-server.

## 2. The BFF Pattern
BFF aims at hiding the OAuth2 tokens from the browser. In this pattern, rich applications (Angular, React, Vue, etc.) are secured with sessions on a middle-ware, the BFF, which is the only OAuth2 client and replaces session cookie with an access-token before forwarding a request to the resource-server.

There is a big trend toward this pattern because it is considered more secure as access-tokens are :
- kept on the server instead of being exposed to the browser (and frequently to Javascript code)
- delivered to OAuth2 confidential clients (browser apps can't keep a secret and are "public" clients)

Keep in mind that sessions are a common attack vector and that this two conditions must be met:
- session cookie should be `Secured` (exchanged over https only) and `HttpOnly` (hidden to Javascript code)
- CSRF protection must be enabled on the BFF (because browser app security relies on sessions)

When a browser application first tries to access REST resources:
1. the BFF redirects the user to the authorization-server
2. the user authenticates
3. the authorization-server redirects back to the BFF with an authorization code
4. the BFF fetches OAuth2 tokens from the authorization-server and stores it in session
5. the BFF forwards the initial request to the resource-server with the access-token as Authorization header

## 3. `spring-cloud-gateway` as BFF
Spring cloud gateway is super easy to configure as a BFF:
- make it an OAuth2 **client**
- activate the `TokenRelay` filter
- serve both the API and the UI through it

### 3.1. Authorization-Server Prerequisites
A client should be declared on the authorization-server for the BFF. As this client will run on a server we trust, it can be "confidential" (clients running in a browser can't keep a secret and have to be "public"). This adds to security as it reduces risk that tokens are emitted for a malicious client (but a firewall restricting authorization-server `token` endpoint access to BFF server would be nice).

For this tutorial, we'll assume that a confidential client with `client-id=spring-addons-confidential` is available. Remind to pick `client-secret`, we'll need it to configure the BFF.

As we intend to authenticate users, next thing to check is that authorization-code flow is activated for our client.

Last, the BFF must be added to post-login and post-logout allowed URIs as well as to allowed origins.

### 3.2. Keycloak Configuration
You might skip this section if you are using another OIDC authorization-server (instead, refer to your provider documentation to implement the prerequisites listed above).

In administration console, got to `clients`
- create a new client with `spring-addons-confidential` as `Client ID` and click `Next`
- enable `Client authentication`, disable `Direct access grants`, enable `Service accounts roles` and click `Save`
- secret is then accessible from `credentials` tab
- got to `Settings` tab and set (change the scheme to https if you enable SSL in your Spring boot apps and adapt the port if you use another one):
  * `http://localhost:7443/*` as `Valid redirect URIs`
  * `http://localhost:7443/*` as `Valid post logout redirect URIs`
  * `http://localhost:7443` as `Web origins`
- save

### 3.3. `spring-cloud-gateway` configuration
From [https://start.spring.io](https://start.spring.io) download a new project with `spring-cloud-starter-gateway` and `spring-boot-starter-oauth2-client` dependencies.

Enable web-flux security on the boot application:
```java
@SpringBootApplication
@EnableWebFluxSecurity
public class BffApplication {

    public static void main(String[] args) {
        SpringApplication.run(BffApplication.class, args);
    }

}
```

Configure application properties with
- OAuth2 client
- TokenRelay
- two routes (one for the resource-server and the other for the browser app):
```yaml
server:
  port: 7443
  ssl:
    enabled: false

spring:
  security:
    oauth2:
      client:
        provider:
          keycloak:
            issuer-uri: http://localhost:8442/realms/master
            user-name-attribute: preferred_username
        registration:
          spring-addons-confidential:
            provider: keycloak
            client-id: spring-addons-confidential
            client-secret: change-me
            authorization-grant-type: authorization_code
            scope: openid,profile,email
  cloud:
    gateway:
      default-filters:
      - TokenRelay=
      - RemoveRequestHeader=Cookie
      - DedupeResponseHeader=Access-Control-Allow-Credentials Access-Control-Allow-Origin
      routes:
      - id: users
        uri: http://localhost:6443/users
        predicates:
        - Path=/users/**
      - id: ui
        uri: http://localhost:4200/
        predicates:
        - Path=/ui/**
```

You might also consider defining a `SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_SPRING_ADDONS_CONFIDENTIAL_CLIENT_SECRET` environment variable instead of putting the secret in your properties file.

## 4. Resource-Server
We will use `com.c4-soft.springaddons:spring-addons-webmvc-jwt-resource-server:6.0.12`, a thin wrapper arround `spring-boot-starter-oauth2-resource-server`.

This resource-server will expose a single `/users/me` endpoint returning the claims of the OAuth2 access-token inserted by the BFF as authorization header. This endpoint could be used by the browser application to get the user OpenID data that was requested as `scope` by the BFF when initiating the authorization-code flow.

From [https://start.spring.io](https://start.spring.io) download a new project with `spring-boot-starter-web` dependency and then add this two dependencies:
```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-webmvc-jwt-resource-server</artifactId>
    <version>6.0.12</version>
</dependency>
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-webmvc-jwt-test</artifactId>
    <version>6.0.12</version>
    <scope>test</scope>
</dependency>
```

Then add this bean to your boot application to switch sucessful authorizations from `JwtAuthenticationToken` to `OAuthentication<OpenidClaimSet>`:
```java
@Bean
OAuth2AuthenticationFactory authenticationFactory(Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
    return (bearerString, claims) -> new OAuthentication<>(new OpenidClaimSet(claims),
            authoritiesConverter.convert(claims), bearerString);
}
```

Here is the @Controller we will be using:
```java
@RestController
@RequestMapping("/users")
public class UsersController {

    @GetMapping("/me")
    public OpenidClaimSet getClaims(OAuthentication<OpenidClaimSet> auth) {
        return auth.getAttributes(); 
    }
}
```

Along with its unit-tests asserting that only authenticated users can access `/users/me`:
```java
@WebMvcTest(controllers = UsersController.class)
@AutoConfigureAddonsWebSecurity
class UsersControllerTest {
    @Autowired
    MockMvcSupport api;

    @Test
    void givenRequestIsNotAuthorized_whenGetMe_thenUnauthorized() throws Exception {
        api.get("/users/me").andExpect(status().isUnauthorized());
    }

    @Test
    @OpenId
    void givenUserIsAuthenticated_whenGetMe_thenOk() throws Exception {
        api.get("/users/me").andExpect(status().isOk());
    }
}
```

And last the configuration properties:
```yaml
server:
  port: 6443
  ssl:
    enabled: false

com:
  c4-soft:
    springaddons:
      security:
        issuers:
          - location: http://localhost:8442/realms/master
            authorities:
              claims:
                - realm_access.roles
                - resource_access.spring-addons-confidential.roles
        cors:
          - path: /users
        permit-all:
```

## 5. Browser client
From that point, you should be able to query the BFF for the claims in the access-token associated to your session: [http://localhost:7443/users/me](http://localhost:7443/users/me) (as seen at point 2., first request will be redirected to the authorization-server for authentication).

An important thing to note regarding security restriction about samesite cookies, CORS, etc. is we will serve the Angular application through the Gateway.

### 5.1. Creating the Application
```bash
ng new angular --create-application=false
cd angular
ng g app --routing=true --style=scss bff-ui
```

As we will use a dedicated route for the UI behind the gateway, let's say `/ui`, we will edit `Angular.json` to add `"baseHref": "/ui/",` to `projects` -> `bff-ui` -> `architect` -> `build` -> `options`

Now, if we start the angular app with `ng serve`, we should be able to browse to [http://localhost:7443/ui](http://localhost:7443/ui). As current gateway configuration requires all requests to be authorized, we might have to authenticate before first accessing the Angular UI.

### 5.2. Querying the Resource-Server from the Angular Application
First thing to do is to import `HttpClientModule` in our `app.module.ts`:
```typescript
import { HttpClientModule } from '@angular/common/http';
...
  imports: [
    HttpClientModule,
...
```
Then we can replace the `AppComponent`:
```typescript
import { HttpClient } from '@angular/common/http';
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent {
  public claims?: any

  constructor(private http: HttpClient) {}

  me() {
    this.http.get('http://localhost:7443/users/me').subscribe(resp => this.claims = resp)
  }
}
```
```html
<button (click)="me()">Fetch claims</button>

<p>{{claims | json}}</p>
```

Et voilà! Now, by [browsing to the UI](http://localhost:7443/ui), and clicking the button, we get the claims in the access-token delivered to the BFF when authenticating on the authorization-server (check in Chrome debug console, this token is nowhere to be found, not even in a Secured HttpOnly cookie).