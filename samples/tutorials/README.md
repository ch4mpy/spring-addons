# Securing Spring Applications With OAuth2
We will see various ways to configure OAuth2 security in Spring Spring Boot 3 applications.

Jump to:
- [1. OAuth2 essentials](#oauth_essentials)
- [2. Tutorials scenarios](#scenarios)
- [3. Prerequisites](#prerequisites)


## 1. <a name="oauth_essentials"/>OAuth2 essentials
OAuth2 client and resource-server configuration are quite different. **If you're not sure about the definitions, needs and responsibilities of those two, please please take 3 minutes to read this section before you start.**

### 1.1 Actors
- **resource-owner**: think of it as end-user. Most frequently a physical person, but can be a client authenticated with client-credential (see below)
- **authorization-server**: the server issuing and certifying resource-owners and clients identities
- **client**: a piece of software which needs to access resources on one or more resource-servers. **It is responsible for acquiring tokens from the authorization server and authorizing its requests to resource-servers.**
- **resource-server**: an API (most frequently REST). It responds to clients requests. **It should not care about login, logout or any OAuth2 flow.** From its point of view, all that matters is if a request is authorized with an access-token, if this token is valid (not expired, emitted by an issuer it trusts, not altered, etc.) and if it should allow access to the requested resource based on the token claims.

### 1.2. Flows
There are quite a few but 3 are of interest for us: authorization-code, client-credentials and refresh-token.

Whatever the flow used, once the client has tokens, it can authorize its requests to resource-servers: set an `authorization` header with a `Bearer` access-token.

Resource-server validates the token and retrieves user details either by:
- using a local JWT decoder which only requires authorization-server public key (retrieved once for all requests)
- submitting token to authorization-server introspection end-point (one call for each and every authorized request it processes, which can cause performance drop)

#### 1.2.1. Authorization-Code
**Used to authenticate a client on behalf of an end-user (physical persons).** 
1. client redirects the unauthorized user to the authorization-server which handles authentication with forms, cookies, biometry or whatever it likes
2. once user authenticated, the authorization-server redirects him back to the client with a `code` to be used once
3. client contacts authorization-server to exchanges the `code` for an access-token (and optionally ID & refresh tokens)

![authorization-code flow](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/authorization-code_flow.png)

#### 1.2.2. Client-Credential
**Used to authenticate client as itself** (without the context of a user). It usually provides the authorization-server with a client-id and client-secret. **This flow can only be used with clients running on a server you trust** (capable of keeping a secret actually "secret") and excludes all services running in a browser or a mobile app (code can be reverse engineered to read secrets).

#### 1.2.3. Refresh-Token
The client sends the refresh-token to the authorization-server which responds with fresh tokens. The refresh-token should not be sent to any other server than the authorization-server.

### 1.3. Tokens
#### 1.3.1. Token Format
A **JWT** is a JSON Web Token. It is used primarily as access or ID token with OAuth2. JWTs can be validated on their own: just authorization-server public signing key is required for that.

In OAuth2, **opaque tokens** can be used instead of JWTs, but it requires introspection: clients and resource-servers have to send a request to authorization-server to ensure the token is valid and get token "attributes" (equivalent to JWT "claims"). This process can have serious performance impact compared to JWT validation.

#### 1.3.2. Access-Token
Pretty much like a paper proxy you could give to someone else to vote for you. It contains as minimum following attributes:
- issuer: the authorization-server which emitted the token (police officer or alike who certified identities of people who gave and recieved proxy)
- subject: resource-owner unique identifier (person who grants the proxy)
- scope: what this token can be used for (did the resource owner grant a proxy for voting, managing a bank account, get a parcell at post-office, etc.)
- expiry: until when can this token be used

A token to be sent by client as Bearer `Authorization` header in its requests to resource-server. Access-tokens content should remain a concern of authorization and resource servers only (client should not try to read access-tokens)

#### 1.3.3. Refresh-Token
A token to be sent by client to authorization-server to get new access-token when it expires (or preferably just before). Refresh-token lifespan is usually quite long and can be used to get many access-tokens. If leaked, user is exposed to an import identity usurpation risk. As a consequence, clients should be very careful about the way it stores tokens and it should make sure it communicates refresh-tokens only to the authorization-server which emitted it.

#### 1.3.4. ID-Token
Part of OpenID extension to OAuth2. A token to be used by client to get user info.

### 1.4. Scope
It is important to note that it is not what the user is allowed to do in the system (like roles, permissions, etc.), but what **he allowed a client to do in his name**. You might think of it as a mask applied on resource-owner resources before a client accesses it.

As so, it makes it a bad candidate for authorities source in spring-security and we'll have to provide our own authorities mapper to make role based security decisions.


## 2. <a name="scenarios"/>Tutorials Scenarios
### 2.1. [`resource-server_with_jwtauthenticationtoken`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_jwtauthenticationtoken)
Create a very flexible (but verbose) security configuration for resource-server with just the "official" Spring Boot starter: `spring-boot-starter-oauth2-resource-server`.

Going through this tutorial will help you understand what is auto-configured by `spring-addons-*-*-resource-server` starters (and its value): **with almost zero Java conf and just a few properties, the configured resource server accepts identities from 3 heterogeneous authorization-servers** (each using different claims for user name and roles):
- a local Keycloak realm
- an Auth0 instance
- a Cognito instance

### 2.2. [`resource-server_with_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_oauthentication)
Demos how to use a custom OAuth2 `Authentication` implementation: `OAthentication<OpenidClaimSet>` with typed accessors to OpenID claims.

### 2.3. [`resource-server_with_specialized_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_specialized_oauthentication)
Builds on top of preceding, showing how to 
- extend `OAthentication<OpenidClaimSet>` implementation to add private claims of your own
- tweek `spring-addons-webmvc-jwt-resource-server` auto-configuration
- enrich security SpEL

### 2.4. [`resource-server_with_additional-header`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_additional-header)
Use a custom header, in addition to the access-token, to build a custom authentication.

### 2.5. [`resource-server_with_introspection`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_introspection)
Quite like `resource-server_with_oauthentication`, using token introspection instead of JWT decoder. Please note this is likely to have performance impact.

### 2.6. [`resource-server_with_ui`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_ui)
Add a security filter-chain for specific routes. This enables to use a client filter chain for the UI resources (with OAuth2login), the default filter-chain for all other routes being designed for REST API (as done in other tutorials).

### 2.7. [BFF](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/bff)
Introduction to the **B**ackend **F**or **F**rontend pattern with `spring-cloud-gateway` as middle-ware between a rich browser application secured with sessions and a Spring OAuth2 resource-server.

## 3. <a name="prerequisites"/>Prerequisites
To run this tutorials you will need a minimum of one OIDC authorization server and a REST client like [Postman](https://www.postman.com/). 

You'll also need to know the private-claim your authorization-servers put username and roles into. There is no standard. Keycloak uses `realm_access.roles` (and `resource_access.{clientId}.roles` if client roles mapper is activated), but other authorization-servers will use something else. You can use tools like https://jwt.io to inspect access-tokens and figure out which claim is used by an issuer for roles.

### 3.1. Authorization-Servers
The samples are all configured to accept identities from 3 sources:
  * a [local Keycloak realm](https://www.keycloak.org/)
  * [Auth0](https://auth0.com/pricing)
  * [Cognito]([https://auth0.com/pricing](https://portal.aws.amazon.com/gp/aws/developer/registration/index.html?pg=cognitoprice&cta=herobtn))

Keycloak is open-source and free. Both Auth0 and Cognito propose free plans which are enough to run the tutorials and samples. You'll have to register your own instances and clients to get your own client-id and client-secrets and update configuration files.

Resource-servers configuration in this tutorial explicitly state that a 401 (unauthorized) is returned when authorization is missing or invalid (no redirection to authorization server login page). It is client responsibility to acquire and maintain valid access-tokens with a flow that authorization server accepts (this does not not always involve a login form: for instance, client credentials and refresh-token don't).

### 3.2. SSL
It is important to work with https when exchanging access-tokens, otherwise tokens can be leaked and user identity stolen. For this reason, many tools and libs will complain if you use http. If you don't have one already, [generate a self-signed certificate](https://github.com/ch4mpy/self-signed-certificate-generation) for your dev machine.

### 3.3. Keycloak configuration
Here is sample configuration for [Keycloak power by Quarkus](https://www.keycloak.org/downloads):
```
http-port=8442
https-key-store-file=C:/path/to/certificate.jks
https-key-store-password=change-me
https-port=8443
```
Then start Keycloak with `start-dev` command line argument:
- on Windows: `C:\keycloak-install-dir\bin\kc.bat start-dev`
- on Linux / Mac: `/keycloak-install-dir/bin/kc.sh start-dev`

This will make Keycloak available on https://localhost:8443

### 3.4. Keycloak Clients
First create a `spring-addons-public` client for applications to authenticate users using authorization-code flow:
![public client creation screen-shot](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/spring-addons-public.png)

You need to add a few URIs (redirect, postlogout and origin). We'll use https://localhost:4200 for Angular app served by dev-server over https, but you can use anything you like (Don't forget to save once you set URIs):
![public client creation screen-shot](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/public-urls.png).

Then add `spring-addons-confidential` client for client-credentials flow:
![public client creation screen-shot](https://github.com/ch4mpy/spring-addons/blob/master/.readme_resources/spring-addons-confidential.png)

### 3.5. Realm roles
Tutorials expect some users to be granted with `NICE` authority. This will require them to be granted with `NICE` "realm role" in Keycloak. An alternative would be to define this role for `spring-addons-public` and enable client roles mapper (clients => spring-addons-public => Client scopes => spring-addons-public-dedicated => Add predefined mapper)

### 3.6. Users
Lets create two users for our live tests:
- `Brice` with `NICE` role granted
- `Igor` without `NICE` role

Don't forget to set a password for those users.
