# Samples
Authorization and resource servers to illustrate various ways to use OAuth2ClaimSetAuthentication:
 * JWT or opaque (introspected) tokens
 * Authorities embedded in token claims by authorization-server or managed by resource-server
 
I provide with end-to-end test project (which packages the two others to be sure fat-jars are available).
Test cases starts authorization and resource servers with different profiles and uses a `TestRestClient` to demo tokens retrieval and protected resources access.

There is some rather advanced configuration to handle profiles described below and manage services startup, communication and shutdown on random available ports.
 
## Choosing token format
By default, user-agent, authorization-server and resource-server exchange opaque Bearer tokens
and resource-server retrieves claims from authorization-server `/introspect` end-point.

You can switch to JWT by activating **jwt** profile on **both** applications.
Resource-server will then read claims from the token itself (`/introspect` end-point not exposed anymore).

## Choosing authorities lookup mode
By default, the resource-server retrieves authorities from H2: `authorities` claim is ignored.
Initialization script for this database is the regular one for spring-boot: data.sql in resources folder.

By activating the **authorities-claim** profile on **both** applications, you can switch from database to token claim lookup: 
* authorization-server adds an `authorities` claim containing user granted authorities names
* resource server then retrieves authorities from this claim instead of searching for it by "subject" in a H2 database.

## Configured data:
You might open authorization-server and resource-server configuration files to confirm values below.

Authorization-server listening on port `8080`.

Token end-point is `https://localhost:8080/oauth/token`.

Three authorization-server clients:
 * `user-agent` / `secret`: to get access and refresh tokens with `showcase` scope using `password` grant flow (see below for users credentials)
   using your favorite user-agent (Postman, web-browser, ...)
 * `showcase-resource-server` / `secret`: to query claims with `showcase` scope at `/introspect` end-point. Resource-server uses it.
   You can use it too to reproduce introspection query (with Postman for instance)
 * `actuator` / `secret`: to check application status and trigger shutdown

Three users:
 * `user` / `password`: has `"showcase:ROLE_USER"` on authorization-server and `"ROLE_USER"` in resource-server H2 database
 * `admin` / `password`: has `["showcase:ROLE_USER", "showcase:AUTHORIZED_PERSONEL"]` on authorization-server and `["ROLE_USER", "ROLE_ADMIN"]` in H2
 * `jpa` / ` password`: no authority on authorization-server and `["ROLE_USER", "AUTHORIZED_PERSONEL"]` in H2

Resource-server listening on port `8090`.

Three resource end-points
 * `https://localhost:8090/greeting` accessible to any authenticated user (valid bearer token in authorization header), displays token subject
 * `https://localhost:8090/restricted/greeting` accessible only to users granted with `showcase:AUTHORIZED_PERSONEL` authority
 * `https://localhost:8090/claims` accessible to any authenticated user, displays token claims 
   (depending on the profile, either embedded in JWT or from introspection end-point)
 
So, depending on **authorities-claim** profile being active or not on resource-server, you will access `https://localhost:8090/restricted/greeting`
with either `admin` or `jpa` user only (`AUTHORIZED_PERSONEL` is required).
   