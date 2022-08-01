# Tutorials for securing Spring resource-servers with OAuth2 JWTs

## Quick reminders

A JWT is a Json Web Token. It is used primarly as access or ID token with OAuth2.

OAuth2 defines 4 actors:
- resource-owner: think of it as end-user. Most frequently a physical person, but can be a client authenticated with client-credential (see below)
- resource-server: an API (most frequently REST)
- client: a piece of softawre which needs to access resources on one or more resource-servers
- authorization-server: the server issuing and certifying identities for resource-owners and clients

OAuth2 flows. There are quite a few but 2 are of interest for us:
- authorization code: useful to authenticate end-users (physical persons). 
  1. Unauthorized user is redirected to authorization-server (request includes client-id, requested scopes, possibly audience, and more)
  2. Authorization-server handles authentication (with forms, cookies, biometry or whatever it likes)
  3. once user authentified, he is redirected to client with a `code` to be used once
  4. client contacts authorization-server to exchanges the `code` for an access-token (and optionnaly a refresh-token)
- client credentials: the client sends client id and secret to authorization server which returns an access-token. To be used to authenticate a client itself (no user context). This must be limited to clients running on a **server you trust** (capable of keeping a secret actually "secret") and excludes all services running in a browser or a mobile app (code can be reverse engineered to read secrets).

Token: pretty much like a paper proxy you could give to someone else to vote for you. It contains as minimum following attributes:
- issuer: the authorization-server which emitted the token (police officer or alike who certified identities of people who gave and recieved proxy)
- subject: resource-owner unique identifier (person who grants the proxy)
- scope: what this token can be used for (did the resource owner grant a proxy for voting, managing a bank account, get a parcell at post-office, etc.)
- expiry: untill when can this token be used

Access-token: a token to be sent by client as Bearer `Authorization` header in its requests to resource-server. Access-tokens content should remain a concern of authorization and resource servers only (client should not try to read access-tokens)

Refresh-token: a token to be sent by client to authorization-server to get new access-token when it expires (or preferably just before).

ID-token: a token to be used by client to get user info.

scope: defines what the user allowed a client to do in his name (not what the user is allowed to do in the system). You might think of it as a mask applied on resource-owner resources before a client accesses it.

OpenID: a standard on top of OAuth2 with, among other things, standard claims

## Tutorials scenarios
### resource-server_with_jwtauthenticationtoken
Create a spring-boot resource-server with libraries and components from spring only: `spring-boot-starter-oauth2-resource-server` lib and `JwtAuthenticationToken`.

It configures the app with common options for resource-servers:
- multi-tenancy (user identities from several isuers)
- CORS (required for services serving REST API only, not UI components)
- CSRF
- public routes and enabled anonymous
- non-public routes restricted to authenticated users (fine grained security rules annotated on `@Controller`s methods with `@PreAuthorize`)
- 401 unauthorized (instead of 302 redirect to login) when request is issued to protected resource with missing or invalid authorization header
- stateless session management
- forced HTTPS if SSL enabled

### resource-server_with_oauthentication
Same features as preceding with 
- much less Java configuration thanks to `spring-security-oauth2-webmvc-addons` (or `spring-security-oauth2-webflux-addons`)
- `OAthentication<OpenidClaimSet>` with typesafe accessors to OpenID claims

### resource-server_with_specialized_oauthentication
Builds on top of preceding, showing how to 
- extend `Authentication` implementation to private claims of your own
- tweek `spring-security-oauth2-webmvc-addons` auto-configuration
- enrich security SpEL
