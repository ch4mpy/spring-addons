# Spring-addons

Set of tools I find useful to work with Spring-framework.
For now it is focused on spring-security with OAuth2, but could grow.

July 2019 breaking news: jars are now available on maven-central!

Something like following Maven configuration should be enough:
``` xml
	<dependencies>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-addons</artifactId>
			<version>${project.version}</version>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-test-oauth2-addons</artifactId>
			<version>${project.version}</version>
			<scope>test</scope>
		</dependency>
	</dependencies>
```

I added a few READMEs to get you started. You might also refer to unit-tests and sample projects to get inspiration.

## oauth2 library

Java implementation of some OAuth2 concepts.

At beginning, I wrote this just to get a better grasp of the specs, but I ended to use it instead of some Spring concepts and implementations.

Please browse to [oauth2 module](https://github.com/ch4mpy/spring-addons/tree/master/oauth2) for more details.

## spring-security-oauth2-addons

I'm not a great supporter of spring-security OAuth2 tokens abstraction and `Authentication` implementations.
I prefer using an implementation of my own instead: `OAuth2ClaimSetAuthentication<? extends UnmodifiableClaimSet>`.

Also, I don't quite agree with the way spring-security processes scopes.

Last, I provide basic tooling to retrieve authorities from token claims (other than "scope" and if authorities are claim embedded, off course).

Browse to [spring-security-oauth2-addons](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-addons) for more details

## `spring-security-oauth2-test-addons`

You'll find there tooling to unit-test not only OAuth2 `@Controller` but also any other kind of `@Component` (such as `@Service`).

More details in [`spring-security-oauth2-test-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-test-oauth2-addons) module.

## Samples
I provide with sample authorization and resource servers to illustrate all of above.
I also demo client communication with both authorization and resource servers in an end-to-end tests project in four different configurations:
* JWT with authorities embedded in token claims
* JWT without authorities claim (resource-server queries it from H2 DB using token subject)
* opaque token introspection with authorities embedded in token claims
* opaque token introspection without authorities claim (resource-server queries it from H2 DB using token subject)
See [`samples`](https://github.com/ch4mpy/spring-addons/tree/master/samples) for more details.
