# Servlet OAuth2 Client with Login, Logout and Authorities Mapping
In this tutorial, we'll configure a servlet (WebMVC) Spring Boot 3 application as an OAuth2 client with login, logout and authorities mapping to enable RBAC using roles defined on OIDC Providers.

## 1. Project Initialization
We start after [prerequisites](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#2-prerequisites), and consider that we have a minimum of 1 OIDC Provider configured (2 would be better) and users with and without `NICE` role declared on each OP.

### 1.1. Spring Boot Starter
As usual, we'll start with http://start.spring.io/ adding the following dependencies:
- Spring Web
- OAuth2 Client
- lombok

### 1.2. Application Properties
Once the project unpacked, replace the `src/main/resources/application.properties` with the following `src/main/resources/application.yaml`:
```yaml
scheme: http
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
keycloak-secret: change-me
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
cognito-secret: change-me
auth0-issuer: https://dev-ch4mpy.eu.auth0.com/
auth0-secret: change-me

server:
  ssl:
    enabled: false
      
spring:
  lifecycle:
    timeout-per-shutdown-phase: 30s
  security:
    oauth2:
      client:
        provider:
          keycloak:
            issuer-uri: ${keycloak-issuer}
          cognito:
            issuer-uri: ${cognito-issuer}
          auth0:
            issuer-uri: ${auth0-issuer}
        registration:
          keycloak-confidential-user:
            authorization-grant-type: authorization_code
            client-name: a local Keycloak instance
            client-id: spring-addons-confidential
            client-secret: ${keycloak-secret}
            provider: keycloak
            scope: openid,profile,email,offline_access
          cognito-confidential-user:
            authorization-grant-type: authorization_code
            client-name: Amazon Cognito
            client-id: 12olioff63qklfe9nio746es9f
            client-secret: ${cognito-secret}
            provider: cognito
            scope: openid,profile,email
          auth0-confidential-user:
            authorization-grant-type: authorization_code
            client-name: Auth0
            client-id: TyY0H7xkRMRe6lDf9F8EiNqCo8PdhICy
            client-secret: ${auth0-secret}
            provider: auth0
            scope: openid,profile,email,offline_access

---
scheme: https
keycloak-port: 8443

server:
  port: 7443
  ssl:
    enabled: true

spring:
  config:
    activate:
      on-profile: ssl
```
There are few things worth noting here:
- we defined 3 different providers with a `authorization_code` client registration for each. This means that user should be prompted to pick one for authenticating (prompt is skipped if only one `authorization_code` client registration is configured).
- there is a `ssl` profile to serve this app over SSL in which the port the application binds to is something else than `80` or `8080` ([because of `PortMapperImpl` usage in servlet applications](https://github.com/spring-projects/spring-security/issues/12307))
- you must replace issuer URIs, as well as client IDs and secrets you got when following [prerequisites](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#2-prerequisites) (remove providers and registrations you did not configure)

### 1.3. Static Index Page
To have something to see once we're authenticated, let's define this `src/main/resources/static/index.html` page :
```html
<!DOCTYPE HTML>
<html>

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>Servlet Client</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
</head>

<body>
<div class="container">
    <h1 class="form-signin-heading">Static Index</h1>
    <a href="/login"><button type="button">Login</button></a>
    <a href="/logout"><button type="button">Logout</button></a>
</div>
</body>
```
We can now run the app and browse to [http://localhost:8080](http://localhost:8080).

At first glance, things seam to be working: we can login on any of the configured OIDC Providers:
- before login, we can't access index and are redirect to login instead
- after login on any of the configured, we can access the index
- after logout, we can't access the index anymore

But with a little more testing, we face a first issue: if we login again on an OIDC Providers we were already identified on, then we are not prompted for our credentials (login happens silently). To solve that, we'll have to configure [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) so that a session invalidation on our client is propagated to the OP.

## 2. RP-Initiated Logout
Spring provides with a `LogoutSuccessHandler` for OIDC Providers implementing the [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html): `OidcClientInitiatedLogoutSuccessHandler`. But do override some of the security filter-chain configuration, we have to provide a full `SecurityFilterChain` bean.

### 2.1. Standard RP-Initiated Logout
An OAuth2 client security filter-chain for an application needing to authenticate users will contain:
- login
- logout
- sessions (enabled by default)
- CSRF protection (required because of sessions and enabled by default with session repository)
- some access control allowing unauthorized users to access at minimum the resources for login and authorization-code flow

Let's implement that:
```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {
    @Bean
    SecurityFilterChain clientSecurityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepo) throws Exception {
        http.oauth2Login();
        http.logout(logout -> {
            final var handler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepo);
            handler.setPostLogoutRedirectUri("{baseUrl}");
            logout.logoutSuccessHandler(handler);
        });
        http.authorizeHttpRequests(ex -> ex.requestMatchers("/login/**", "/oauth2/**").permitAll().anyRequest().authenticated());
        return http.build();
    }
}
```
Great! Logout now works as expected with Keycloak, but it's another story with Auth0 and Cognito which diverge from the standard: the `end_session_endpoint` is not listed in `.well-known/openid-configuration` and the parameter name for `post_logout_redirect_uri` is not standard.

### 2.2. Non-Standard RP-Initiated Logout
Let's write our own `LogoutSuccessHandler` to specify the logout URI as well as parameter name for post-logout URI.

For that, let's first decorate our Boot application with `@ConfigurationPropertiesScan` and then declare configuration properties:
```java
@Data
@Configuration
@ConfigurationProperties(prefix = "logout")
public class LogoutProperties {
    private Map<String, ProviderLogoutProperties> registration = new HashMap<>();

    @Data
    static class ProviderLogoutProperties {
        private URI logoutUri;
        private String postLogoutUriParameterName;
    }
}
```
Adding those properties to the yaml (mind the provider IDs which must be the same as those under `spring.security.oauth2.client.registration`):
```yaml
logout:
  registration:
    cognito-confidential-user:
      logout-uri: https://spring-addons.auth.us-west-2.amazoncognito.com/logout
      post-logout-uri-parameter-name: logout_uri
    auth0-confidential-user:
      logout-uri: ${auth0-issuer}v2/logout
      post-logout-uri-parameter-name: returnTo
```
Now, we can define a logout success handler parsing this configuration for non standard RP-Initiated Logout (taking "inspiration" from Spring's `OidcClientInitiatedLogoutSuccessHandler`):
```java
@RequiredArgsConstructor
static class AlmostOidcClientInitiatedLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
    private final LogoutProperties.ProviderLogoutProperties properties;
    private final ClientRegistration clientRegistration;
    private final String postLogoutRedirectUri;

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken oauthentication && authentication.getPrincipal() instanceof OidcUser oidcUser) {
            final var endSessionUri = UriComponentsBuilder.fromUri(properties.getLogoutUri()).queryParam("client_id", clientRegistration.getClientId())
                    .queryParam("id_token_hint", oidcUser.getIdToken().getTokenValue())
                    .queryParam(properties.getPostLogoutUriParameterName(), postLogoutRedirectUri(request).toString()).toUriString();
            return endSessionUri.toString();
        }
        return super.determineTargetUrl(request, response, authentication);
    }

    private String postLogoutRedirectUri(HttpServletRequest request) {
        if (this.postLogoutRedirectUri == null) {
            return null;
        }
        // @formatter:off
        UriComponents uriComponents = UriComponentsBuilder.fromUriString(request.getRequestURL().toString())
                .replacePath(request.getContextPath())
                .replaceQuery(null)
                .fragment(null)
                .build();

        Map<String, String> uriVariables = new HashMap<>();
        String scheme = uriComponents.getScheme();
        uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
        uriVariables.put("baseUrl", uriComponents.toUriString());

        String host = uriComponents.getHost();
        uriVariables.put("baseHost", (host != null) ? host : "");

        String path = uriComponents.getPath();
        uriVariables.put("basePath", (path != null) ? path : "");

        int port = uriComponents.getPort();
        uriVariables.put("basePort", (port == -1) ? "" : ":" + port);

        uriVariables.put("registrationId", clientRegistration.getRegistrationId());

        return UriComponentsBuilder.fromUriString(this.postLogoutRedirectUri)
                .buildAndExpand(uriVariables)
                .toUriString();
        // @formatter:on
    }
}
```
This handler is fine for non-standard OPs, but if want to keep Spring's logout success handler for Keycloak (and avoid defining logout properties for it), we need a facade for the two implementations we now have:
```java
static class DelegatingOidcClientInitiatedLogoutSuccessHandler implements LogoutSuccessHandler {
    private final Map<String, LogoutSuccessHandler> delegates;

    public DelegatingOidcClientInitiatedLogoutSuccessHandler(
            InMemoryClientRegistrationRepository clientRegistrationRepository,
            LogoutProperties properties,
            String postLogoutRedirectUri) {
        delegates = StreamSupport.stream(clientRegistrationRepository.spliterator(), false)
                .collect(Collectors.toMap(ClientRegistration::getRegistrationId, clientRegistration -> {
                    final var registrationProperties = properties.getRegistration().get(clientRegistration.getRegistrationId());
                    if (registrationProperties == null) {
                        final var handler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
                        handler.setPostLogoutRedirectUri(postLogoutRedirectUri);
                        return handler;
                    }
                    return new AlmostOidcClientInitiatedLogoutSuccessHandler(registrationProperties, clientRegistration, postLogoutRedirectUri);
                }));
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException,
            ServletException {
        if (authentication instanceof OAuth2AuthenticationToken oauthentication) {
            delegates.get(oauthentication.getAuthorizedClientRegistrationId()).onLogoutSuccess(request, response, authentication);
        }
    }

}
```
This handler switches between Spring's `OidcClientInitiatedLogoutSuccessHandler` and our `AlmostOidcClientInitiatedLogoutSuccessHandler` depending on the configuration properties.

Last we need to update the security filter-chain to use the new `DelegatingOidcClientInitiatedServerLogoutSuccessHandler`:
```java
@Bean
SecurityFilterChain
        clientSecurityFilterChain(HttpSecurity http, InMemoryClientRegistrationRepository clientRegistrationRepository, LogoutProperties logoutProperties)
                throws Exception {
    http.oauth2Login();
    http.logout(logout -> {
        logout.logoutSuccessHandler(new DelegatingOidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository, logoutProperties, "{baseUrl}"));
    });
    http.authorizeHttpRequests(ex -> ex.requestMatchers("/login/**", "/oauth2/**").permitAll().anyRequest().authenticated());
    return http.build();
}
```

## 3. Roles Mapping
We'll implement a mapping of Spring Security authorities from OpenID private claims with the following specifications:
- possibly use several claims as source, all of those claims being a string array or a single string of comma separated values (Keycloak for instance can provide with roles in `realm_access.roles` and `resource_access.{client-id}.roles`)
- configure case processing and prefix independently for each claim (for instance use `SCOPE_` prefix for scopes in `scp` claim and `ROLE_` prefix for roles in `realm_access.roles` one)
- provide with a different configuration for each provider (Keycloak, Auth0 and Cognito all use different private claims for user roles)

### 3.1. Dependencies
To ease roles claims parsing, we'll use [json-path](https://central.sonatype.com/artifact/com.jayway.jsonpath/json-path/2.8.0). Let's add it to our dependencies:
```xml
<dependency>
    <groupId>com.jayway.jsonpath</groupId>
    <artifactId>json-path</artifactId>
</dependency>
```

### 3.2. Application Properties
Then, we need some additional configuration properties to provide with the flexibility we specified above:
```java
@Data
@Configuration
@ConfigurationProperties(prefix = "authorities-mapping")
public class AuthoritiesMappingProperties {
    private IssuerAuthoritiesMappingProperties[] issuers = {};

    @Data
    static class IssuerAuthoritiesMappingProperties {
        private URL uri;
        private ClaimMappingProperties[] claims;

        @Data
        static class ClaimMappingProperties {
            private String jsonPath;
            private CaseProcessing caseProcessing = CaseProcessing.UNCHANGED;
            private String prefix = "";

            static enum CaseProcessing {
                UNCHANGED, TO_LOWER, TO_UPPER
            }
        }
    }

    public IssuerAuthoritiesMappingProperties get(URL issuerUri) throws MisconfigurationException {
        final var issuerProperties = Stream.of(issuers).filter(iss -> issuerUri.equals(iss.getUri())).toList();
        if (issuerProperties.size() == 0) {
            throw new MisconfigurationException("Missing authorities mapping properties for %s".formatted(issuerUri.toString()));
        }
        if (issuerProperties.size() > 1) {
            throw new MisconfigurationException("Too many authorities mapping properties for %s".formatted(issuerUri.toString()));
        }
        return issuerProperties.get(0);
    }

    static class MisconfigurationException extends RuntimeException {
        private static final long serialVersionUID = 5887967904749547431L;

        public MisconfigurationException(String msg) {
            super(msg);
        }
    }
}
```
We'll also need the yaml properties matching this configuration:
```yaml
authorities-mapping:
  issuers:
  - uri: ${keycloak-issuer}
    claims:
    - jsonPath: $.realm_access.roles
    - jsonPath: $.resource_access.*.roles
  - uri: ${cognito-issuer}
    claims:
    - jsonPath: $.cognito:groups
  - uri: ${auth0-issuer}
    claims:
    - jsonPath: $.roles
    - jsonPath: $.groups
    - jsonPath: $.permissions
```

### 3.3. `GrantedAuthoritiesMapper`
According to [the doc](https://docs.spring.io/spring-security/reference/servlet/oauth2/login/advanced.html#oauth2login-advanced-map-authorities), we have two options:
- providing a `GrantedAuthoritiesMapper` bean
- providing and configuring an `OAuth2UserService<OidcUserRequest, OidcUser>`

We'll opt for the first solution: it's lighter, simpler and is enough for what we need, using the template from the doc as starting point:
```java
@Component
@RequiredArgsConstructor
static class GrantedAuthoritiesMapperImpl implements GrantedAuthoritiesMapper {
    private final AuthoritiesMappingProperties properties;

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

        authorities.forEach(authority -> {
            if (OidcUserAuthority.class.isInstance(authority)) {
                final var oidcUserAuthority = (OidcUserAuthority) authority;
                final var issuer = oidcUserAuthority.getIdToken().getClaimAsURL(JwtClaimNames.ISS);
                mappedAuthorities.addAll(extractAuthorities(oidcUserAuthority.getIdToken().getClaims(), properties.get(issuer)));

            } else if (OAuth2UserAuthority.class.isInstance(authority)) {
                try {
                    final var oauth2UserAuthority = (OAuth2UserAuthority) authority;
                    final var userAttributes = oauth2UserAuthority.getAttributes();
                    final var issuer = new URL(userAttributes.get(JwtClaimNames.ISS).toString());
                    mappedAuthorities.addAll(extractAuthorities(userAttributes, properties.get(issuer)));

                } catch (MalformedURLException e) {
                    throw new RuntimeException(e);
                }
            }
        });

        return mappedAuthorities;
    };

    private static
            Collection<GrantedAuthority>
            extractAuthorities(Map<String, Object> claims, AuthoritiesMappingProperties.IssuerAuthoritiesMappingProperties properties) {
        return Stream.of(properties.claims).flatMap(claimProperties -> {
            Object claim;
            try {
                claim = JsonPath.read(claims, claimProperties.jsonPath);
            } catch (PathNotFoundException e) {
                claim = null;
            }
            if (claim == null) {
                return Stream.empty();
            }
            if (claim instanceof String claimStr) {
                return Stream.of(claimStr.split(","));
            }
            if (claim instanceof String[] claimArr) {
                return Stream.of(claimArr);
            }
            if (Collection.class.isAssignableFrom(claim.getClass())) {
                final var iter = ((Collection) claim).iterator();
                if (!iter.hasNext()) {
                    return Stream.empty();
                }
                final var firstItem = iter.next();
                if (firstItem instanceof String) {
                    return (Stream<String>) ((Collection) claim).stream();
                }
                if (Collection.class.isAssignableFrom(firstItem.getClass())) {
                    return (Stream<String>) ((Collection) claim).stream().flatMap(colItem -> ((Collection) colItem).stream()).map(String.class::cast);
                }
            }
            return Stream.empty();
        }).map(SimpleGrantedAuthority::new).map(GrantedAuthority.class::cast).toList();
    }
}
```
We can now use, in our Spring application, the roles defined on any of the OIDC Providers our user is identified against.

### 3.4. Role Based Access Control
To demo RBAC, let's define a new `src/main/resources/static/nice.html` page which should be accessible to `NICE` users only:
```html
<!DOCTYPE HTML>
<html>

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>Servlet Client</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
</head>

<body>
<div class="container">
    <h1 class="form-signin-heading">You are so nice!</h1>
</div>
</body>
```
This off course requires to update the security configuration as follow:
```java
http.authorizeHttpRequests(ex -> ex
        .requestMatchers("/login/**", "/oauth2/**").permitAll()
        .requestMatchers("/nice.html").hasAuthority("NICE")
        .anyRequest().authenticated());
```
Now, only the users we granted with `NICE` role when configuring the OIDC Providers during [prerequisites](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#2-prerequisites) should be able to see the [http://localhost:8080/nice.html](http://localhost:8080/nice.html) page ([https://localhost:7443/nice.html](https://localhost:7443/nice.html) if `ssl` profile is active).

## 4. Preventing Simultaneous Identities
Our index page being static (as well as the generated login one), it has no notion of the user being authenticated. As a consequence, an already identified user can login with a second OIDC Provider.

If there is no fundamental problem with that (a user may actually have a variety of numeric identities across as many OPs as he likes), Spring does not support that out of the box: `OAuth2AuthenticationToken` is bound to a single `OAuth2User` which supports only one `subject` (the one from the last authentication), and the authorized client repository requires that `subject` to retrieve an authorized client.

As a result, if we login sequentially with several OP in our app, only the last identity is available and logout will terminate the session on the last OP only.

As working around `InMemoryAuthorizedClientRepository` is a rather complicated task, what we'll implement next is a guard to prevent authenticated users from logging in: they'll have to logout before they can login again.

### 4.1. Thymeleaf Index
Our first step will be replacing the static index with a template adapting to the user authentication status: display a `login` button to unauthorized users and a `logout` button to those already authenticated.

For that, let's add [Thymeleaf starter](https://central.sonatype.com/artifact/org.springframework.boot/spring-boot-starter-thymeleaf/3.0.5) to our dependencies:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
```

Then we need a `@Controller` to check the user authentication status and set a `Model` accordingly:
```java
@Controller
public class IndexController {

    @GetMapping("/")
    public String getIndex(Authentication auth, Model model) {
        model.addAttribute("isAuthenticated", auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken));
        return "index";
    }
}
```

Last we can copy `src/main/resources/static/index.html` to `src/main/resources/templates/` and edit it to use the model we just set in the controller:
```java
<!DOCTYPE HTML>
<html xmlns:th="http://www.thymeleaf.org">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>Servlet Client</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
</head>

<body>
<div class="container">
    <h1 class="form-signin-heading">Dynamic Index</h1>
    <a th:if="!${isAuthenticated}" href="/login"><button type="button">Login</button></a>
    <a th:if="${isAuthenticated}" href="/logout"><button type="button">Logout</button></a>
</div>
</body>
```

### 4.2. Security Configuration Update
The security rules need an update. We now want to:
- allow access to index to all users (authenticated or not)
- allow access to login page only to non-authenticated users

The first rule is easy to implement: add `/` to the list of `permitAll()`, but the second requires to insert a filter before the login page one (there is a special "login page" filter which bypasses requests authorization):
```java
static class LoginPageFilter extends GenericFilterBean {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        final var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null
                && auth.isAuthenticated()
                && !(auth instanceof AnonymousAuthenticationToken)
                && ((HttpServletRequest) request).getRequestURI().equals("/login")) {
            ((HttpServletResponse) response).sendRedirect("/");
        }
        chain.doFilter(request, response);
    }
}
```
We can then update the security filter-chain configuration as follow:
```java
@Bean
SecurityFilterChain
        clientSecurityFilterChain(HttpSecurity http, InMemoryClientRegistrationRepository clientRegistrationRepository, LogoutProperties logoutProperties)
                throws Exception {
    http.addFilterBefore(new LoginPageFilter(), DefaultLoginPageGeneratingFilter.class);
    http.oauth2Login();
    http.logout(logout -> {
        logout.logoutSuccessHandler(new DelegatingOidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository, logoutProperties, "{baseUrl}"));
    });
    http.authorizeHttpRequests(ex -> ex
            .requestMatchers("/login").access(new UnauthenticatedAccessManager())
            .requestMatchers("/", "/login/**", "/oauth2/**").permitAll()
            .anyRequest().authenticated());
    return http.build();
}
```

## 5. Conclusion
In this tutorial we configured a servlet OAuth2 client with login, logout and roles mapping.

But wait, what we did here is pretty verbose and we'll need it in almost any OAuth2 client we write. Do we really have to write all that again and again? Not really: this repo provides with a [`spring-addons-webfmvc-client`](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-addons-webmvc-client) Spring Boot starter just for that, and if for whatever reason you don't want to use that one, you can still write [your own starter](https://docs.spring.io/spring-boot/docs/current/reference/html/features.html#features.developing-auto-configuration) to wrap the configuration we wrote here.

Also, what if we actually need to users to have several authorized clients at the same time (for instance be authenticated on Google and Facebook at the same time to query Google API and Facebook graph from the same client)? Well, as suggested in previous section, you can provide with an alternate `OAuth2AuthorizedClientRepository`. This repo client starters propose such an implementation storing an authentication per issuer in the user session and then resolving the right one (with its subject) before trying to retrieve an authorized client. Again, if you don't want to use those starters, you can still write [your own](https://docs.spring.io/spring-boot/docs/current/reference/html/features.html#features.developing-auto-configuration).

Last, you might have a look a integration tests in source code to see how access control rules to `/`, `/login` and `nice.html` are verified with mocked security contexts.