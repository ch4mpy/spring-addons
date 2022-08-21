# Securing Spring resource-servers with OAuth2
We will see various ways to configure Spring OAuth2 resource-servers with the following very common options:
- CORS (required for services serving REST API only, UI components being served from an other socket, host or domain)
- CSRF
- public routes and enabled anonymous
- non-public routes restricted to authenticated users (fine grained security rules annotated on @Controllers methods with @PreAuthorize)
- 401 unauthorized (instead of 302 redirect to login) when request is issued to protected resource with missing or invalid authorization header
- stateless session management
- forced HTTPS if SSL enabled
- multi-tenancy (accept user identities issued by more than just one issuer). Only introspection doesn't (hard to figure out the issuer of an opaque string and so to send introspection request to the right authorization-server).

For resource-servers with security based on JWT decoding, you should read it in following order:
1. [`resource-server_with_jwtauthenticationtoken`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_jwtauthenticationtoken) which requires quite some Java conf but help understand what `spring-addons` alternate staters for resource-server auto-configure.
2. [`resource-server_with_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_oauthentication) demoes the configuration cut-downs which can be achieved with `spring-addons-webmvc-jwt-resource-server`, `spring-addons-webflux-jwt-resource-server`, `spring-addons-webmvc-introspecting-resource-server` or `spring-addons-webflux-introspecting-resource-server` starters
3. [`resource-server_with_specialized_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_specialized_oauthentication) show how to change `spring-addons-*-*-resource-server` starters auto-configuration to match advanced buisiness security requirements: parsing private-claims, extending `Authentication` implementation and enriching security DSL

As an alternate, if you are interseted in token introspection, you should refer to [`resource-server_with_introspection`](resource-server_with_introspection).

## Volcabulary reminder
A **JWT** is a Json Web Token. It is used primarly as access or ID token with OAuth2. JWTs can be validated on their own: just authorization-server public signing key is required for that.

In OAuth2, **opaque tokens** can be used instead of JWTs, but it requires introspection: clients and resource-servers have to send a request to authorization-server to ensure the token is valid and get token "attributes" (equivalent to JWT "claims"). This process can have serious performance impact compared to JWT validation.

OAuth2 defines 4 **actors**:
- **resource-owner**: think of it as end-user. Most frequently a physical person, but can be a client authenticated with client-credential (see below)
- **resource-server**: an API (most frequently REST)
- **client**: a piece of softawre which needs to access resources on one or more resource-servers
- **authorization-server**: the server issuing and certifying identities for resource-owners and clients

OAuth2 **flows**. There are quite a few but 2 are of interest for us:
- **authorization code**: useful to authenticate end-users (physical persons). 
1. Unauthorized user is redirected from its client (desktop, web or mobile app) to authorization-server which handles authentication with forms, cookies, biometry or whatever it likes
2. once user authentified, he is redirected to client with a `code` to be used once
3. client contacts authorization-server to exchanges the `code` for an access-token (and optionnaly a refresh-token)
4. client sends requests to resource-server with access-token in authorization header
5. resource-servers validates the token and retrieves user details either by using a local JWT decoder which only requires authorization-server public key (retrieved once for all requests) or submitting token to authorization-server introspection endpoint (one call for each and every authorized request it processes, which can cause performance drop)

![authorization-code flow](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/authorization-code_flow.png)

- **client credentials**: the client sends client id and secret to authorization server which returns an access-token. To be used to authenticate a client itself (no user context). This must be limited to clients running on a **server you trust** (capable of keeping a secret actually "secret") and excludes all services running in a browser or a mobile app (code can be reverse engineered to read secrets).

**Token**: pretty much like a paper proxy you could give to someone else to vote for you. It contains as minimum following attributes:
- issuer: the authorization-server which emitted the token (police officer or alike who certified identities of people who gave and recieved proxy)
- subject: resource-owner unique identifier (person who grants the proxy)
- scope: what this token can be used for (did the resource owner grant a proxy for voting, managing a bank account, get a parcell at post-office, etc.)
- expiry: untill when can this token be used

**Access-token**: a token to be sent by client as Bearer `Authorization` header in its requests to resource-server. Access-tokens content should remain a concern of authorization and resource servers only (client should not try to read access-tokens)

**Refresh-token**: a token to be sent by client to authorization-server to get new access-token when it expires (or preferably just before).

**ID-token**: part of OpenID extension to OAuth1. A token to be used by client to get user info.

**scope**: defines what the user allowed a client to do in his name (not what the user is allowed to do in the system). You might think of it as a mask applied on resource-owner resources before a client accesses it.

**OpenID**: a standard on top of OAuth2 with, among other things, standard claims

## Prerequisites
This tutorials are focused on **Spring resource-servers**. To run it, you will need:
- an OIDC authorization server like [Keycloak](https://www.keycloak.org/) or any other of your choice
- a REST client like [Postman](https://www.postman.com/)
- a few configured clients. I recommand following
  * a "public" client: used for web and mobile applications with authorization-code flow
  * a "confidential" client: used by programs you trust (running on servers you trust) with client-credentials flow. This id used for instance by resource-servers for introspecting tokens on authorization-server (in such query, spring-application is actually a client and Keycloak a resource-server, I know this is confusing) or when a micro-service calls another one to be served a resource in its own name (not on behalf of authenticated user). On keycloak, this means setting `confidential` "Access Type" and activating "Service Accounts Enabled".
- a few users with various roles. At least one user should be granted `NICE` authority which is referenced from spring controllers security rules.
- knowledge of the private-claim your authorization-server puts authorities into. There is no standard. Keycloak uses `realm_access.roles` (and `resource_access.{clientId}.roles` if client roles mapper is activated), but other authorization-servers will use something else. You can use tools like https://jwt.io to inspect access-tokens and figure out which claim is used by an issuer for roles.

Resource-servers configuration in this tutorial explicitely state that a 401 (unauthorized) is returned when authorization is missing or invalid (no redirection to authorization server login page). It is client responsiblity to acquire and maintain valid access-tokens with a flow that authorization server accepts (this does not not always involve a login form: for instance, client credentials and refresh-token don't).

Last, default configuration enables CSRF, which is a good thing for production and well handled by serious client libraries, but a bit cumbersome when testing with REST client. You can disable it with `com.c4-soft.springaddons.security.csrf-enabled=false` (or `http.csrf().disable();` in `resource-server_with_jwtauthenticationtoken` web-security-config).

## Tutorials scenarios
### [`resource-server_with_jwtauthenticationtoken`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_jwtauthenticationtoken)
Create a spring-boot resource-server with libraries and components from spring only: `spring-boot-starter-oauth2-resource-server` lib and `JwtAuthenticationToken`.

We'll see that activating all the options listed in introduction requires quite some Java conf, but going through this tutorial will help you understand what is auto-configured by `spring-addons-*-*-resource-server` starters (and why I cerated it).

### [`resource-server_with_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_oauthentication)
Same features as preceding with 
- **almost 0 Java configuration**: thanks to `spring-addons-webmvc-jwt-resource-server` (or `spring-addons-webflux-jwt-resource-server`), a lot is configurable from application properties
- `OAthentication<OpenidClaimSet>` with typed accessors to OpenID claims

### [`resource-server_with_specialized_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_specialized_oauthentication)
Builds on top of preceding, showing how to 
- extend `OAthentication<OpenidClaimSet>` implementation to add private claims of your own
- tweek `spring-addons-webmvc-jwt-resource-server` auto-configuration
- enrich security SpEL

### [`resource-server_with_introspection`](resource-server_with_introspection)
Quite like `resource-server_with_oauthentication`, using token introspection instead of JWT decoder. Please note this is likely to have performance impact and that Authentication type is [constrained to `BearerTokenAuthentication`](https://github.com/spring-projects/spring-security/issues/11661)
