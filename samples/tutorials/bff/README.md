# Implementing the OAuth2 **B**ackend **F**or **F**rontend pattern with Spring Cloud Gateway
Introduction to the OAuth2 **B**ackend **F**or **F**rontend pattern with `spring-cloud-gateway` as middle-ware between a single-page or mobile application secured with sessions cookies and a Spring OAuth2 resource-server secured with JWTs.

Contains sample frontends written with Angular, React (Next.js) and Vue (Vite).

The OAuth2 BFF tutorial is now [on Baeldung](https://www.baeldung.com/spring-cloud-gateway-bff-oauth2).

### Definition
A **B**ackend **F**or **F**rontend is a middleware between a frontend and REST APIs and can be used for very different reasons. Here, we are interested in OAuth2 BFF which is used to bridge between requests authorization using session cookies (as provided by the the frontend) and authorization using Bearer token (as expected by resource servers). Its responsibilities are:
- driving the authorization-code flow using a "confidential" OAuth2 client
- maintaining sessions and storing tokens in it
- replacing the session cookie with the access token in session before forwarding a request from the frontend to a resource server

###  Benefits over public OAuth2 clients
The main value is safety:

the BFF running on a server we trust, the authorization server token endpoint can be protected with a secret and firewall rules to allow only requests from our backend. This greatly reduces the risk that tokens are issued to malicious clients.
tokens are kept on the server (sessions), which prevents it from being stolen on end-user devices by malicious programs. Usage of session cookies requires protection against CSRF, but cookies can be flagged with HttpOnly, Secure and SameSite, in which case the cookie protection on the device is enforced by the browser itself. As a comparison, a SPA configured as public client needs access to tokens and we have to be very careful with how this tokens are stored: if a malicious program manages to read an access or refresh token, the consequences can be disastrous for the user (identity usurpation).
The other benefit is the complete control it gives on user session and the ability to instantly revoque an access.

### Cost
A BFF is an additional layer in the system and it is on the critical path. In production, this implies:
- more resources (a little)
- more latency (very little)
- more monitoring & failure recovery

Also, the resource servers behind the BFF can (and should) be stateless, but the OAuth2 BFF itself need sessions and this requires specific actions to make it scalable and fault tolerant.

We can easily package Spring Cloud Gateway into a native image using Spring Boot Maven and Gradle plugins. This makes it super lightweight and bootable in a fraction of a second, but there is always a limit to the traffic it can absorb. When needing more than a single instance, we'll have to either share the session between BFF instances, or use a smart proxy routing all requests from a given device to the same instance.

### Choice of an implementation
Some frameworks implement the OAuth2 BFF pattern without communicating explicitly about it or calling it that way. This is the case for instance of the NextAuth library which uses server components to implement OAuth2 (uses a confidential client in a Node instance on the server). This is enough to benefit from the safety of the OAuth2 BFF pattern.

But because of the very rich Spring ecosystem, there are very few existing solutions as handy as Spring Cloud Gateway when monitoring, scalability and fault tolerance matters:
- spring-boot-starter-actuator dependency provides with powerful auditing features
- Spring Session is a rather simple solution for distributed sessions
- spring-boot-starter-oauth2-client and oauth2Login() handle the authorization-code flow and store tokens in the session
- the TokenRelay= filter replaces the session cookie with the access token in the session when forwarding requests from the frontend to a resource server
