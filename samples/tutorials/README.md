# Securing Spring resource-servers with OAuth2
We will see various ways to configure Spring OAuth2 resource-servers with the following very common options:
- CORS (required for services serving REST API only, UI components being served from an other socket, host or domain)
- disabled sessions (state-less session management): the state is hold in the access-token
- disabled CSRF (safe because of disabled sessions)
- public routes (and enabled anonymous to access it)
- non-public routes restricted to authenticated users with fine grained security rules annotated on @Controllers methods with @PreAuthorize
- 401 unauthorized (instead of 302 redirect to login) when request is issued to protected resource with missing or invalid authorization header
- force all trafic over HTTPS if SSL is enabled
- multi-tenancy (accept user identities issued by more than just one issuer). Only introspection doesn't (hard to figure out the issuer of an opaque string and so to send introspection request to the right authorization-server).

For resource-servers with security based on JWT decoding, you should read it in following order:
1. [`resource-server_with_jwtauthenticationtoken`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_jwtauthenticationtoken) which requires quite some Java conf but help understand what `spring-addons` alternate staters for resource-server auto-configure.
2. [`resource-server_with_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_oauthentication) demoes the configuration cut-downs which can be achieved with `spring-addons-webmvc-jwt-resource-server`, `spring-addons-webflux-jwt-resource-server`, `spring-addons-webmvc-introspecting-resource-server` or `spring-addons-webflux-introspecting-resource-server` starters
3. [`resource-server_with_specialized_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_specialized_oauthentication) show how to change `spring-addons-*-*-resource-server` starters auto-configuration to match advanced business security requirements: parsing private-claims, extending `Authentication` implementation and enriching security DSL
4. [`resource-server_with_additional-header`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_additional-header) show how to add data from a header to what is retrieved from the access-token

As an alternate, if you are interested in token introspection, you should refer to [`resource-server_with_introspection`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_introspection).

You might want to end with [`resource-server_with_ui`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_ui) if your application also serves UI elements which need OAuth2 login or [`BFF`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/bff) if you are interested in making `spring-cloud-gateway` a **B**ackend **F**or **F**rontend.

## Content
- [Tutorials scenarios](#scenarios)
- [OAuth2 essentials](#oauth_essentials)
- [Prerequisites](#prerequisites)


## <a name="scenarios"/>Tutorials scenarios
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

### [`resource-server_with_additional-header`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_additional-header)
Shows how to use a custom header together with the access token to build a custom authentication 

### [`resource-server_with_introspection`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_introspection)
Quite like `resource-server_with_oauthentication`, using token introspection instead of JWT decoder. Please note this is likely to have performance impact.

### [`resource-server_with_ui`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_ui)
This tutorial shows how to add additional filter-chains for specified routes. This enables to use a client filter chain for the UI resources (with OAuth2login), the default filter-chain for all other routes being designed for REST API (as done in other tutorials).

### [BFF](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/bff)
Introduction to the **B**ackend **F**or **F**rontend pattern with `spring-cloud-gateway` as middle-ware between a rich browser application secured with sessions and a Spring OAuth2 resource-server.


## <a name="oauth_essentials"/>OAuth2 essentials

### Token format
A **JWT** is a JSON Web Token. It is used primarily as access or ID token with OAuth2. JWTs can be validated on their own: just authorization-server public signing key is required for that.

In OAuth2, **opaque tokens** can be used instead of JWTs, but it requires introspection: clients and resource-servers have to send a request to authorization-server to ensure the token is valid and get token "attributes" (equivalent to JWT "claims"). This process can have serious performance impact compared to JWT validation.

### Actors
- **resource-owner**: think of it as end-user. Most frequently a physical person, but can be a client authenticated with client-credential (see below)
- **resource-server**: an API (most frequently REST)
- **client**: a piece of software which needs to access resources on one or more resource-servers
- **authorization-server**: the server issuing and certifying identities for resource-owners and clients

### Flows
There are quite a few but 2 are of interest for us:
- **authorization code**: useful to authenticate end-users (physical persons). 
1. Unauthorized user is redirected from its client (desktop, web or mobile app) to authorization-server which handles authentication with forms, cookies, biometry or whatever it likes
2. once user authenticated, he is redirected back to client with a `code` to be used once
3. client contacts authorization-server to exchanges the `code` for an access-token (and optionally a refresh-token)
4. client sends requests to resource-server with access-token in authorization header
5. resource-servers validates the token and retrieves user details either by 
   - using a local JWT decoder which only requires authorization-server public key (retrieved once for all requests)
   - submitting token to authorization-server introspection end-point (one call for each and every authorized request it processes, which can cause performance drop)

![authorization-code flow](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/authorization-code_flow.png)

- **client credentials**: the client sends client id and secret to authorization server which returns an access-token. To be used to authenticate a client itself (no user context). This must be limited to clients running on a **server you trust** (capable of keeping a secret actually "secret") and excludes all services running in a browser or a mobile app (code can be reverse engineered to read secrets).

### Tokens
#### Access-token
Pretty much like a paper proxy you could give to someone else to vote for you. It contains as minimum following attributes:
- issuer: the authorization-server which emitted the token (police officer or alike who certified identities of people who gave and recieved proxy)
- subject: resource-owner unique identifier (person who grants the proxy)
- scope: what this token can be used for (did the resource owner grant a proxy for voting, managing a bank account, get a parcell at post-office, etc.)
- expiry: until when can this token be used

A token to be sent by client as Bearer `Authorization` header in its requests to resource-server. Access-tokens content should remain a concern of authorization and resource servers only (client should not try to read access-tokens)

#### Refresh-token
A token to be sent by client to authorization-server to get new access-token when it expires (or preferably just before).

#### ID-token
Part of OpenID extension to OAuth1. A token to be used by client to get user info.

### scope
It is important to note that it is not what the user is allowed to do in the system what **he allowed a client to do in his name**. You might think of it as a mask applied on resource-owner resources before a client accesses it.

As so, it makes it a bad candidate for authorities source in spring-security and we'll have to provide our own authorities mapper to make role based security decisions.


## <a name="prerequisites"/>Prerequisites
This tutorials are focused on **Spring resource-servers**. To run it, you will need:
- an OIDC authorization server like [Keycloak](https://www.keycloak.org/) or any other of your choice
- a REST client like [Postman](https://www.postman.com/)
- a few configured clients:
  * a "public" client: used for authorization-code flow (desktop, web and mobile applications authenticating users)
  * a "confidential" client: used for client-credentials flow (programs you trust, running on servers you trust, acting in their own name, not on on behalf of a user). This id used for instance by resource-servers for introspecting tokens on authorization-server  or when a micro-service calls another one to be served a resource in its own name (not on behalf of authenticated user).
- a few users with various roles. At least one user should be granted `NICE` authority which is referenced from spring controllers security rules.
- knowledge of the private-claim your authorization-server puts authorities into. There is no standard. Keycloak uses `realm_access.roles` (and `resource_access.{clientId}.roles` if client roles mapper is activated), but other authorization-servers will use something else. You can use tools like https://jwt.io to inspect access-tokens and figure out which claim is used by an issuer for roles.

Resource-servers configuration in this tutorial explicitly state that a 401 (unauthorized) is returned when authorization is missing or invalid (no redirection to authorization server login page). It is client responsibility to acquire and maintain valid access-tokens with a flow that authorization server accepts (this does not not always involve a login form: for instance, client credentials and refresh-token don't).

Last, default configuration enables CSRF, which is a good thing for production and well handled by serious client libraries, but a bit cumbersome when testing with REST client. You can disable it with `com.c4-soft.springaddons.security.csrf-enabled=false` (or `http.csrf().disable();` in `resource-server_with_jwtauthenticationtoken` web-security-config).

### SSL
It is important to work with https when exchanging access-tokens, otherwise tokens can be leaked and user identity stolen. For this reason, many tools and libs will complain if you use http. If you don't have one already, [generate a self-signed certificate](https://github.com/ch4mpy/self-signed-certificate-generation) for your dev machine.

### Keycloak configuration
Here is sample configuration for [Keycloak power by Quarkus](https://www.keycloak.org/downloads):
```
http-enabled=false
https-key-store-file=C:/path/to/certificate.jks
https-key-store-password=change-me
https-port=8443
```
Then start Keycloak with `start-dev` command line argument:
- on Windows: `C:\keycloak-install-dir\bin\kc.bat start-dev`
- on Linux / Mac: `/keycloak-install-dir/bin/kc.sh start-dev`

This will make Keycloak available on https://localhost:8443

### Clients
First create a `spring-addons-public` client for applications to authenticate users using authorization-code flow:
![public client creation screen-shot](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/spring-addons-public.png)

You need to add a few URIs (redirect, postlogout and origin). We'll use https://localhost:4200 for Angular app served by dev-server over https, but you can use anything you like (Don't forget to save once you set URIs):
![public client creation screen-shot](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/public-urls.png).

Then add `spring-addons-confidential` client for client-credentials flow:
![public client creation screen-shot](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/spring-addons-confidential.png)

### Realm roles
Tutorials expect some users to be granted with `NICE` authority. This will require them to be granted with `NICE` "realm role" in Keycloak. An alternative would be to define this role for `spring-addons-public` and enable client roles mapper (clients => spring-addons-public => Client scopes => spring-addons-public-dedicated => Add predefined mapper)

### Users
Lets create two users for our live tests:
- `Brice` with `NICE` role granted
- `Igor` without `NICE` role

Don't forget to set a password for those users.
