# Securing Spring Applications With OAuth2
This tutorials are focused on configuring OAuth2 security in Spring Spring Boot 3 applications with OIDC Provider(s).

**You should carefully read the [OAuth2 essentials](#oauth_essentials) section before rushing to a specific tutorial**. This will likely save you a lot of time.

Then, once you have determined if the application to configured is based on WebMVC or WebFulx, if it's a client or resource-server, and [configured at least an OIDC Provider](#prerequisites), then you should refer the [Tutorials scenarios](#scenarios) and pick one matching your needs.

Jump to:
- [1. OAuth2 essentials](#oauth_essentials)
- [2. Prerequisites](#prerequisites)
- [3. Tutorials scenarios](#scenarios)


## 1. <a name="oauth_essentials"/>OAuth2 essentials
OAuth2 client and resource-server configuration are quite different. **Spting provides with different starters for a reason**. If you're not sure about the definitions, needs and responsibilities of those two, please please take 3 minutes to read this section before you start.

### 1.1 Actors
- **resource-owner**: think of it as end-user. Most frequently a physical person, but can be a batch or whatever trusted program authenticated with client-credential (or even a device authenticated with a flow we'll skip) 
- **authorization-server**: the server issuing and certifying resource-owners and clients identities. It is sometimes refered to as *issuer* or *OIDC Provider* (*OP*).
- **client**: a piece of software which needs to access resources on one or more resource-servers. **It is responsible for acquiring tokens from the authorization server and authorizing its requests to resource-servers**, and as so to handle OAuth2 flows. It is sometimes refered to as *Relying Party* (*RP*).
- **resource-server**: an API (most frequently REST). **It should not care about login, logout or any OAuth2 flow.** From its point of view, all that matters is if a request is authorized with a valid access-token and taking access decisions based on it.

### 1.2. Client VS Resource Server Configuration
As already wrote, the responsibilities and security requirements are quite different for the two. Lets explore that in more details.

#### 1.2.1. Need for Sessions
**Resource servers can usually be configured as stateless (without session)**. The "state" is associated with the access token which is enough to restore the security context of a request. This has quite a few valuable benefits for scalabilty and fault tolerance: any resource server instance can process any request without the need of sharing a session. Also, the access token protects against CSRF attacks and, if it is rotated frequently enough (every minute or so), against BREACH attacks too!

**Clients consumed by browsers are secured with session cookies, not access tokens**. This exposes it to CSRF and BREACH attacks, and we'll have to configure specific mitigations for that. Also, as soon as scalability and fault tolerance are a concern, we'll have to pull the session out of the client instances.

#### 1.2.2. Requests Authorization
Resource servers expect requests to protected resources to be authorized: have an `Authorization` header containing a `Bearer` access token. It's responsibilities are to check the validity of this token (issuer, audience, expiration time, etc.) and then decide if it should grant the requested resource based on the token claims (inside the token or introspected from it).

Clients are responsible for authorizing their requests: set the `Authorization` header of the requests it send to resource server. Clients have the choice of different OAuth2 flows to get tokens from the authorization server (see next section for details).

User login is part of OAuth2 `authorization-code` flow. As a consequence, **OAuth2 login (and logout) only make sense on OAuth2 clients configured with `authorization-code` flow**.

To send requests to a secured resource server, you'll have to use a client capable of sending authorized requests. A few samples:
- REST clients with UI like Postman
- a "rich" browser application (Angular, React, Vue, etc.) configured as public client with an OAuth2 client library to handle flows, tokens storage and requests authorization
- programmatic REST client (`WebClient`, `@FeignClient`, `RestTemplate`, ...) used to call an OAuth2 secured API (resource server) from another micro-service (any Spring `@Component` like a MVC `@Controller` rendering a Thymeleaf template)
- a BFF. **B**ackend **F**or **F**rontend is a pattern in which a middleware (the BFF) on the server is used to hide OAuth2 tokens from the browser. The requests between the browser and the BFF are secured with sessions. The BFF is responsible for login, logout, storing tokens in session and replacing session cookie with OAuth2 access token before forwarding a request from the browser to resource server(s). `spring-cloud-gateway` can be used as BFF with `spring-boot-starter-oauth2-client` and the `TokenRelay` filter.

#### 1.2.3. Should I use `spring-boot-starter-oauth2-client` or `spring-boot-starter-oauth2-resource-server`?
If the application is a REST API it's a resource server. Configuring it as a client just to enable OAuth2 login and query its REST endpoints with a browser is a mistake: It breaks its "stateless" nature and would work only for GET endpoints. Use `spring-boot-starter-oauth2-resource-server`, do not configure OAuth2 login and require clients to authorize their requests (use Postman or alike for your tests).

Use `spring-boot-starter-oauth2-client` only if the application serves UI templates or is used as BFF. In that case only, will login & logout be configured in Spring application. 

What if the application matches both cases above (for instance exposes publicly both a REST API and a Thymeleaf UI to manipulate it)? As seen earlier, the configuration requirements are too different to stand in the same security filter-chain, but **it is possible to define more than one filter-chain if the first(s) in `@Order` are defined with `securityMatcher` to define to which routes it apply**: a request path is checked against each security matcher in order and the first match defines which `SecurityFilterChain` bean will be applied to the request.

### 1.3. Flows
There are quite a few but 3 are of interest for us: authorization-code, client-credentials and refresh-token.

Whatever the flow used, once the client has tokens, it can authorize its requests to resource-servers: set an `authorization` header with a `Bearer` access-token.

Resource-server validates the token and retrieves user details either by:
- using a local JWT decoder which only requires authorization-server public key (retrieved once for all requests)
- submitting token to authorization-server introspection end-point (one call for each and every authorized request it processes, which will cause performance drop)

#### 1.3.1. Authorization-Code
**Used to authenticate a client on behalf of an end-user (physical persons).**
0. client and resource server fetch OpenID configuration from the OIDC Provider
1. client redirects the unauthorized user to the authorization server. If the user already has an opened session on the authorization server, the login succeeds silently. Otherwize, the user is prompted for credentials, biometry MFA tokens or whatever has been configured on the OP.
2. once user authenticated, the authorization-server redirects the user back to the client with a `code` to be used once
3. client contacts authorization-server to exchanges the `code` for an access-token (and optionally ID & refresh tokens)
4. client sends an authorized request to the resource server (a request with an access token in `Authorization` header)
5. resource server validates access token (using JWT public key fetched once or introspecting each token on the OP) and takes access-control decision

![authorization-code flow](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/authorization-code_flow.png)

In the schematic above, the authorization-code flow starts at step 1 and ends with step 3.

#### 1.3.2. Client-Credential
**Used to authenticate client as itself** (without the context of a user). It usually provides the authorization-server with a client-id and client-secret. **This flow can only be used with clients running on a server you trust** (capable of keeping a secret actually "secret") and excludes all services running in a browser or a mobile app (code can be reverse engineered to read secrets). This flow is frequently used for inter micro-service communication (to fetch configuration, post logs or tracing events, message publication / subscription, ...)

#### 1.3.3. Refresh-Token
The client sends the refresh-token to the authorization-server which responds with new tokens to replace those about to expire. The refresh-token should not be sent to any other server than the authorization-server.

### 1.4. Tokens
#### 1.4.1. Token Format
A **JWT** is a JSON Web Token. It is used primarily as access or ID token with OAuth2. JWTs can be validated on their own: just authorization-server public signing key is required for that.

In OAuth2, **opaque tokens** can be used instead of JWTs, but it requires introspection: clients and resource-servers have to send a request to authorization-server to ensure the token is valid and get token "attributes" (equivalent to JWT "claims"). This process can have serious performance impact compared to JWT validation.

#### 1.4.2. Access-Token
Pretty much like a paper proxy you could give to someone else to vote for you. It contains as minimum following attributes:
- issuer: the authorization-server which emitted the token (police officer or alike who certified identities of people who gave and recieved proxy)
- subject: resource-owner unique identifier (person who grants the proxy)
- scope: what this token can be used for (did the resource owner grant a proxy for voting, managing a bank account, get a parcell at post-office, etc.)
- expiry: until when can this token be used

A token to be sent by client as Bearer `Authorization` header in its requests to resource-server. Access-tokens content should remain a concern of authorization and resource servers only (client should not try to read access-tokens)

#### 1.4.3. Refresh-Token
A token to be sent by client to authorization-server to get new access-token when it expires (or preferably just before). Refresh-token lifespan is usually quite long and can be used to get many access-tokens. If leaked, user is exposed to an import identity usurpation risk. As a consequence, clients should be very careful about the way it stores tokens and it should make sure it communicates refresh-tokens only to the authorization-server which issued it.

#### 1.4.4. ID-Token
Part of OpenID extension to OAuth2. A token to be used by client to get user info.

### 1.5. Scope, Roles, Permissions, Groups, etc.
It is important to note that `scope` is not what the user is allowed to do in the system (like roles, permissions, etc.), but what **he allowed a client to do on his behalf**. You might think of it as a mask applied on resource-owner resources before a client accesses it.

As so, it makes it a bad candidate for authorities source in spring-security and we'll have to provide our own authorities converter to make role based security decisions with authorities mapped from the private claims our authorization server uses for roles, permissions, groups, etc..

## 2. <a name="prerequisites"/>Prerequisites
To run this tutorials you will need a minimum of one OIDC Provider (authorization server), but to appreciate its full potential, having the 3 referenced in the next sub-section would be nice.

You'll also find a REST client with a UI pretty handy to fetch tokens from the authorization server and send authorized tests requests to your resource server instances. [Postman](https://www.postman.com/) is a famous sample.

Last, you'll have to know the private-claim your authorization-servers put username and roles into. There is no standard. Keycloak uses `realm_access.roles` (and `resource_access.{clientId}.roles` if client roles mapper is activated), but other authorization-servers will use something else. You can use tools like https://jwt.io to inspect access-tokens and figure out which claim is used by an issuer for roles.

### 2.1. Authorization-Servers
The samples are all configured to accept identities from 3 sources:
  * a [local Keycloak realm](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/keycloak.md) Keycloak is open-source and free
  * [Auth0](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/auth0.md)
  * [Cognito](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/cognito.md)

Both Auth0 and Cognito propose free plans which are enough to run the tutorials and samples. You'll have to register your own instances and clients to get your own client-id and client-secrets and update configuration files.

Remember to update the tutorials configuration with the OIDC Providers you set up.

### 2.2. SSL
It is important to work with https when exchanging access-tokens, otherwise tokens can be leaked and user identity stolen. For this reason, many tools and libs will complain if you use http. If you don't have one already, [generate a self-signed certificate](https://github.com/ch4mpy/self-signed-certificate-generation) for your dev machine.

## 3. <a name="scenarios"/>Tutorials Scenarios
### 3.1. [`resource-server_with_jwtauthenticationtoken`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_jwtauthenticationtoken)
Create a very flexible (but verbose) security configuration for resource-server with just the "official" Spring Boot starter: `spring-boot-starter-oauth2-resource-server`.

Going through this tutorial will help you understand what is auto-configured by `spring-addons-*-*-resource-server` starters (and its value): **with almost zero Java conf and just a few properties, the configured resource server accepts identities from 3 heterogeneous authorization-servers** (each using different claims for user name and roles):
- a local Keycloak realm
- an Auth0 instance
- a Cognito instance

### 3.2. [`resource-server_with_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_oauthentication)
Demos how to use a custom OAuth2 `Authentication` implementation: `OAthentication<OpenidClaimSet>` with typed accessors to OpenID claims.

### 3.3. [`resource-server_with_specialized_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_specialized_oauthentication)
Builds on top of preceding, showing how to 
- extend `OAthentication<OpenidClaimSet>` implementation to add private claims of your own
- tweek `spring-addons-webmvc-jwt-resource-server` auto-configuration
- enrich security SpEL

### 3.4. [`resource-server_with_additional-header`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_additional-header)
Use a custom header, in addition to the access-token, to build a custom authentication.

### 3.5. [`resource-server_with_introspection`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_introspection)
Quite like `resource-server_with_oauthentication`, using token introspection instead of JWT decoder. Please note this is likely to have performance impact.

### 3.6. [`resource-server_with_ui`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_ui)
Add a security filter-chain for specific routes. This enables to use a client filter chain for the UI resources (with OAuth2login), the default filter-chain for all other routes being designed for REST API (as done in other tutorials).

### 3.7. [BFF](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/bff)
Introduction to the **B**ackend **F**or **F**rontend pattern with `spring-cloud-gateway` as middle-ware between a rich browser application secured with sessions and a Spring OAuth2 resource-server.
