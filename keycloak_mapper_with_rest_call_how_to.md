# How to build a Keycloak mapper to add a private-claim with data from a web-service

Let's say we have a security model where users can grant some of their authorizations to some other users of their choice.

To implement this, we'll proceed in two steps:
- create a RESTful Spring micro-service to CRUD grants between users
- create a Keycloak "mapper" calling this service to add a `proxies` private-claim to tokens

You can find complete source code (including a minimal Angular UI) in [this repo](https://github.com/ch4mpy/user-proxies)

## Spring resource-server for proxies between users

### Domain model
- "grants" will be simple strings like `READ_A` or `EDIT_B`
- users will be identified by subject. Any other unique non-null key like database ID, e-mail or preferred-username could have been chosen.
- a "Proxy" holds a validity period (null end means it never ends) and the "grants" a `grantingUser` provides a `grantedUser` with

### Initiate project

#### Save time with a maven archetype
``` bash
mvn archetype:generate \
  -DarchetypeCatalog=remote \
  -DarchetypeGroupId=com.c4-soft.springaddons \
  -DarchetypeArtifactId=spring-webmvc-archetype-multimodule \
  -DarchetypeVersion=4.2.0 \
  -DgroupId=com.c4-soft.howto \
  -DartifactId=user-proxies \
  -Dversion=1.0.0-SNAPSHOT \
  -Dapi-artifactId=proxies-api \
  -Dapi-path=user-proxies
```

#### DTOs
Replace DTOs with the following:
``` java
@XmlRootElement
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProxyDto implements Serializable {
	private static final long serialVersionUID = 7382907575214377114L;

	@NotNull
	private Long id;

	@NotEmpty
	@NotNull
	private String grantingUserSubject;

	@NotEmpty
	@NotNull
	private String grantedUserSubject;

	@NotNull
	private List<String> grants;

	@NotNull
	private Long start;

	private Long end;
}
```
``` java
@XmlRootElement
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProxyEditDto implements Serializable {
	private static final long serialVersionUID = 7381717131881105091L;

	@NotNull
	private List<String> grants;

	@NotNull
	private Long start;

	private Long end;
}
```
``` java
@XmlRootElement
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserCreateDto implements Serializable {
	private static final long serialVersionUID = 1963318450007215498L;

	@NotNull
	private String subject;

	@NotNull
	@Email
	private String email;

	@NotNull
	private String preferedUsername;

}
```
``` java
@XmlRootElement
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDto implements Serializable {
	private static final long serialVersionUID = -3684504868042067509L;

	@NotNull
	private Long id;

	@NotNull
	private String subject;

	@NotNull
	@Email
	private String email;

	@NotNull
	private String preferedUsername;

}
```
This last DTO represents OpenID response for access-token. It will be used by the mapper itself to get a token (using client credentials) and secure its requests to proxies web-service.
``` java
@XmlRootElement
@Data
public class TokenResponseDto implements Serializable {
	private static final long serialVersionUID = 4995510591526512450L;

	@JsonProperty("access_token")
	private String accessToken;

	@JsonProperty("expires_in")
	private Long expiresIn;

	@JsonProperty("refresh_expires_in")
	private Long refreshExpiresIn;

	@JsonProperty("token_type")
	private String tokenType;

	@JsonProperty("id_token")
	private String idToken;

	@JsonProperty("not-before-policy")
	private Long notBeforePolicy;

	private String scope;
}
```

#### Domain entities and JPA repositories
- edit parent pom to add `hibernate-jpamodelgen` to `annotationProcessorPaths` in `maven-compiler-plugin` configuration:
```xml
							<path>
								<groupId>org.hibernate</groupId>
								<artifactId>hibernate-jpamodelgen</artifactId>
								<version>${hibernate.version}</version>
							</path>
```
- replace domain entity with those two:
``` java
@Entity
@Table(name = "user_proxies", uniqueConstraints = {
		@UniqueConstraint(name = "UniqueProxiedAndGrantedUsers", columnNames = { "granting_user_id", "granted_user_id" }) })
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Proxy {
	@Id
	@GeneratedValue
	private Long id;

	@NotNull
	@ManyToOne(optional = false, cascade = CascadeType.ALL, fetch = FetchType.EAGER)
	@JoinColumn(name = "granting_user_id", updatable = false, nullable = false)
	private User grantingUser;

	@NotNull
	@ManyToOne(optional = false, cascade = CascadeType.ALL, fetch = FetchType.EAGER)
	@JoinColumn(name = "granted_user_id", updatable = false, nullable = false)
	private User grantedUser;

	@NotNull
	@ElementCollection(fetch = FetchType.EAGER)
	@Default
	private List<String> grants = new ArrayList<>();

	@NotNull
	@Column(name = "start_date", nullable = false, updatable = true)
	private Date start;

	@Column(name = "end_date", nullable = true, updatable = true)
	private Date end;
}
```
``` java
@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
	@Id
	@GeneratedValue
	private Long id;

	@Column(nullable = false, unique = true)
	private String subject;

	@Column(nullable = false, unique = true)
	@Email
	private String email;

	@Column(nullable = false, unique = true)
	private String preferedUsername;

	@OneToMany(mappedBy = "grantedUser", cascade = CascadeType.ALL, orphanRemoval = false)
	private List<Proxy> grantedProxies = new ArrayList<>();

	@OneToMany(mappedBy = "grantingUser", cascade = CascadeType.ALL, orphanRemoval = false)
	private List<Proxy> grantingProxies = new ArrayList<>();

	public User(String subject, String email, String preferedUsername) {
		this.subject = subject;
		this.email = email;
		this.preferedUsername = preferedUsername;
	}
}
```
- now JPA repositories `Specification` aware
``` java
public interface ProxyRepository extends JpaRepository<Proxy, Long>, JpaSpecificationExecutor<Proxy> {
	static Specification<Proxy> searchSpec(Optional<String> grantingUserSubject, Optional<String> grantedUserSubject, Optional<Date> date) {
		final var specs =
				Stream
						.of(
								Optional.of(endsAfter(date.orElse(new Date()))),
								grantingUserSubject.map(ProxyRepository::grantingUserSubjectLike),
								grantedUserSubject.map(ProxyRepository::grantedUserSubjectLike),
								date.map(ProxyRepository::startsBefore))
						.filter(Optional::isPresent)
						.map(Optional::get)
						.toList();
		var spec = Specification.where(specs.get(0));
		for (var i = 1; i < specs.size(); ++i) {
			spec = spec.and(specs.get(i));
		}
		return spec;
	}

	static Specification<Proxy> endsAfter(Date date) {
		return (root, query, cb) -> cb.or(cb.isNull(root.get(Proxy_.end)), cb.greaterThanOrEqualTo(root.get(Proxy_.end), date));
	}

	static Specification<Proxy> grantingUserSubjectLike(String grantingUserSubject) {
		return (root, query, cb) -> cb.like(root.get(Proxy_.grantingUser).get(User_.subject), grantingUserSubject);
	}

	static Specification<Proxy> grantedUserSubjectLike(String grantedUserSubject) {
		return (root, query, cb) -> cb.like(root.get(Proxy_.grantedUser).get(User_.subject), grantedUserSubject);
	}

	static Specification<Proxy> startsBefore(Date date) {
		return (root, query, cb) -> cb.lessThanOrEqualTo(root.get(Proxy_.start), date);
	}
}
```
```java
public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {

	Optional<User> findBySubject(String userSubject);

	static Specification<User> searchSpec(String emailOrPreferredUsername) {
		if (!StringUtils.hasText(emailOrPreferredUsername)) {
			return null;
		}

		return Specification
				.where(attibuteLikeIgnoreCase("email", emailOrPreferredUsername))
				.or(attibuteLikeIgnoreCase("preferredUsername", emailOrPreferredUsername));
	}

	private static Specification<User> attibuteLikeIgnoreCase(String attributeName, String needle) {
		return (root, query, criteriaBuilder) -> criteriaBuilder
				.like(criteriaBuilder.lower(root.get(attributeName)), String.format("%%%s%%", needle.trim().toLowerCase()));
	}

}
```

#### DTO <-> domain mappers
``` java
@Mapper(componentModel = ComponentModel.SPRING)
public interface UserMapper {

	UserDto toDto(User domain);

	@Mapping(target = "id", ignore = true)
	@Mapping(target = "grantingProxies", ignore = true)
	@Mapping(target = "grantedProxies", ignore = true)
	void update(@MappingTarget User domain, UserCreateDto dto);

}
```
``` java
@Mapper(componentModel = ComponentModel.SPRING)
public interface UserProxyMapper {

	@Mapping(target = "grantingUserSubject", source = "grantingUser.subject")
	@Mapping(target = "grantedUserSubject", source = "grantedUser.subject")
	ProxyDto toDto(Proxy domain);

	@Mapping(target = "id", ignore = true)
	@Mapping(target = "grantingUser", ignore = true)
	@Mapping(target = "grantedUser", ignore = true)
	void update(@MappingTarget Proxy domain, ProxyEditDto dto);

	default Date toDate(Long epoch) {
		return Optional.ofNullable(epoch).map(Date::new).orElse(null);
	}

	default Long toEpoch(Date date) {
		return Optional.ofNullable(date).map(Date::getTime).orElse(null);
	}
}
```

#### `@RestController`
Here are the required end-points:
- create user entries in proxies database
- retrieve users by part of their e-mail or preferred_username
- CRUD proxies a user is granted with (respectively POST, GET, PUT and DELETE operations) with path `/user/{subject}/proxies/granted`
- retrieve all proxies a user is granting to others `/user/{subject}/proxies/granting`

And following security rules should be enforced:
  - identifed users can edit (POST, PUT, DELETE) their own proxies (current user subject is equal to proxiedUserSubject path variable)
  - users with `PROXIES_ADMIN` authority can edit any user proxies
  - users with a proxy containing `READ_PROXIES` grant for current user can get the proxies they gave and recieved. `EDIT_PROXIES` is required to create, update or delete an other user proxies
  - clients with `AUTHORIZATION_SERVER` role should be able to list the proxies a user is granted with

```java
@RestController
@RequestMapping(path = "/users", produces = { MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE })
@RequiredArgsConstructor
@Tag(name = "Users", description = "CRUD operations for grants delegation between users")
public class UserController {
	private final UserRepository userRepo;
	private final UserMapper userMapper;
	private final ProxyRepository proxyRepo;
	private final UserProxyMapper proxyMapper;

	@GetMapping
	@Operation(description = "Retrieve collection of users.")
	@PreAuthorize("isAuthenticated()")
	public List<UserDto> retrieveByEmailOrPreferredUsernamePart(
			@RequestParam(name = "emailOrPreferredUsernamePart") @Parameter(description = "Mandatory and min length is 4. Case insensitive part of user e-mail or preferredUserName.") @Length(min = 4) String emailOrPreferredUsernamePart,
			@AuthenticationPrincipal ProxiesOidcToken token) {
		return userRepo.findAll(UserRepository.searchSpec(emailOrPreferredUsernamePart)).stream().map(userMapper::toDto).toList();
	}

	@PostMapping
	@Operation(description = "Register a user in proxies service")
	@PreAuthorize("#token.subject == #dto.subject or hasAnyAuthority('USERS_ADMIN')")
	public ResponseEntity<?> create(@RequestBody @Valid UserCreateDto dto, @AuthenticationPrincipal ProxiesOidcToken token) {
		final var user = new User();
		userMapper.update(user, dto);
		return ResponseEntity.created(URI.create(userRepo.save(user).getId().toString())).build();
	}

	@GetMapping("/{subject}")
	@Operation(description = "Retrieve a user by subject")
	@PreAuthorize("isAuthenticated()")
	public UserDto retrieveBySubject(
			@PathVariable(name = "subject", required = false) @Parameter(description = "User subject.") String subject,
			@AuthenticationPrincipal ProxiesOidcToken token) {
		return userRepo
				.findBySubject(subject)
				.map(userMapper::toDto)
				.orElseThrow(() -> new ResourceNotFoundException(String.format("No user with subject %s", subject)));
	}

	@GetMapping("/{subject}/proxies/granted")
	@PreAuthorize("#token.subject == #subject or hasAnyAuthority('AUTHORIZATION_SERVER', 'USERS_ADMIN') or #token.allows(#subject, 'READ_PROXIES')")
	public List<ProxyDto> retrieveGrantedProxies(
			@PathVariable(name = "subject", required = false) @Parameter(description = "User subject.") String subject,
			@AuthenticationPrincipal ProxiesOidcToken token) {
		return proxyRepo
				.findAll(ProxyRepository.searchSpec(Optional.empty(), Optional.ofNullable(subject), Optional.empty()))
				.stream()
				.map(proxyMapper::toDto)
				.toList();
	}

	@GetMapping("/{subject}/proxies/granting")
	@PreAuthorize("#token.subject == #subject or hasAnyAuthority('USERS_ADMIN') or #token.allows(#subject, 'READ_PROXIES')")
	public List<ProxyDto> retrieveGrantingProxies(
			@PathVariable(name = "subject", required = false) @Parameter(description = "User subject.") String subject,
			@AuthenticationPrincipal ProxiesOidcToken token) {
		return proxyRepo
				.findAll(ProxyRepository.searchSpec(Optional.ofNullable(subject), Optional.empty(), Optional.empty()))
				.stream()
				.map(proxyMapper::toDto)
				.toList();
	}

	@PostMapping("/{grantingUserSubject}/proxies/granted/{grantedUserSubject}")
	@Operation(description = "Create grant delegation from \"granting user\" to \"granted user\".")
	@PreAuthorize("#token.subject == #grantingUserSubject or hasAnyAuthority('USERS_ADMIN') or #token.allows(#grantingUserSubject, 'EDIT_PROXIES')")
	public ResponseEntity<?> createProxy(
			@PathVariable(name = "grantingUserSubject") @Parameter(description = "Proxied user subject") @NotEmpty String grantingUserSubject,
			@PathVariable(name = "grantedUserSubject") @Parameter(description = "Granted user subject") @NotEmpty String grantedUserSubject,
			@Valid @RequestBody ProxyEditDto dto,
			@AuthenticationPrincipal ProxiesOidcToken token) {
		final var proxy = Proxy.builder().grantingUser(getUser(grantingUserSubject)).grantedUser(getUser(grantedUserSubject)).build();
		proxyMapper.update(proxy, dto);
		final var created = proxyRepo.save(proxy);
		proxyRepo.saveAll(processOverlaps(created));
		return ResponseEntity.created(URI.create(created.getId().toString())).build();
	}

	@PutMapping("/{grantingUserSubject}/proxies/granted/{grantedUserSubject}/{id}")
	@Operation(description = "Update grant delegation from \"granting user\" to \"granted user\".")
	@PreAuthorize("#token.subject == #grantingUserSubject or hasAnyAuthority('USERS_ADMIN') or #token.allows(#grantingUserSubject, 'EDIT_PROXIES')")
	public ResponseEntity<?> updateProxy(
			@PathVariable(name = "grantingUserSubject") @Parameter(description = "Proxied user subject") @NotEmpty String grantingUserSubject,
			@PathVariable(name = "grantedUserSubject") @Parameter(description = "Granted user subject") @NotEmpty String grantedUserSubject,
			@PathVariable(name = "id") @Parameter(description = "proxy ID") Long id,
			@Valid @RequestBody ProxyEditDto dto,
			@AuthenticationPrincipal ProxiesOidcToken token) {
		final var proxy = getProxy(id, grantingUserSubject, grantedUserSubject);
		proxyMapper.update(proxy, dto);
		proxyRepo.saveAll(processOverlaps(proxy));
		return ResponseEntity.accepted().build();
	}

	@DeleteMapping("/{grantingUserSubject}/proxies/granted/{grantedUserSubject}/{id}")
	@Operation(description = "Delete all grants \"granted user\" had to act on behalf of \"granting user\".")
	@PreAuthorize("#token.subject == #grantingUserSubject or hasAnyAuthority('USERS_ADMIN') or #token.allows(#grantingUserSubject, 'EDIT_PROXIES')")
	public ResponseEntity<?> deleteProxy(
			@PathVariable(name = "grantingUserSubject") @Parameter(description = "Proxied user subject") @NotEmpty String grantingUserSubject,
			@PathVariable(name = "grantedUserSubject") @Parameter(description = "Granted user subject") @NotEmpty String grantedUserSubject,
			@PathVariable(name = "id") @Parameter(description = "proxy ID") Long id,
			OidcAuthentication<OidcToken> auth) {
		final var proxy = getProxy(id, grantingUserSubject, grantedUserSubject);
		proxyRepo.delete(proxy);
		return ResponseEntity.accepted().build();
	}

	private Proxy getProxy(Long id, String grantingUserSubject, String grantedUserSubject) {
		final var proxy = proxyRepo.findById(id).orElseThrow(() -> new ResourceNotFoundException(String.format("No user proxy with ID %s", id)));

		if (!proxy.getGrantingUser().getSubject().equals(grantingUserSubject) || !proxy.getGrantedUser().getSubject().equals(grantedUserSubject)) {
			throw new ProxyUsersUnmodifiableException();
		}

		return proxy;
	}

	private User getUser(String subject) {
		return userRepo.findBySubject(subject).orElseThrow(() -> new ResourceNotFoundException(String.format("No user with subject %s", subject)));
	}

	private List<Proxy> processOverlaps(Proxy proxy) {
		final var proxiesToCheck =
				proxyRepo
						.findAll(
								ProxyRepository
										.searchSpec(
												Optional.of(proxy.getGrantingUser().getSubject()),
												Optional.of(proxy.getGrantedUser().getSubject()),
												Optional.empty()));
		final var modifiedProxies = new ArrayList<Proxy>(proxiesToCheck.size());
		proxiesToCheck.forEach(existing -> {
			if (existing.getId() == proxy.getId()) {
				// skip provided proxy
			} else if (existing.getEnd() != null && existing.getEnd().before(proxy.getStart())) {
				// skip existing ending before provided starts
			} else if (proxy.getEnd() == null) {
				// provided proxy has no end
				if (existing.getStart().after(proxy.getStart()) || existing.getStart().equals(proxy.getStart())) {
					// any existing proxy starting after provided one is deleted
					proxyRepo.delete(existing);
				} else if (existing.getEnd() == null || existing.getEnd().after(proxy.getStart()) || existing.getEnd().equals(proxy.getStart())) {
					// shorten any proxy ending after provided one starts (because of preceding condition, we know it overlaps: starts before provided)
					existing.setEnd(new Date(proxy.getStart().getTime() - 1));
					modifiedProxies.add(existing);
				}
			} else if (existing.getStart().after(proxy.getEnd())) {
				// skip existing starting after provided starts
			} else {
				// existing ending before provided starts already skipped
				existing.setEnd(new Date(proxy.getStart().getTime() - 1L));
				modifiedProxies.add(existing);
			}
		});
		return modifiedProxies;
	}
}
```

## Keycloak mapper
We have a rather advance mapper use-case: the data for the claim to add is to be retrieved from a secured OpenID resource-server (the `/users/{subject}/proxies/granted` end-point from above)

### Requirements
In Keycloak UI:
- create a `proxies-mapper` client 
- in settings, to enable client-credentials flow, set 
  - `confidential` "Access Type"
  - activete "Service Accounts Enabled"
- in roles declare an `AUTHORIZATION_SERVER` role

### Maven project
Here is the pom:
```xml
<project xmlns="http://maven.apache.org/POM/4.0.0"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>com.c4-soft.howto</groupId>
		<artifactId>user-proxies</artifactId>
		<version>1.0.0-SNAPSHOT</version>
		<relativePath>..</relativePath>
	</parent>
	<artifactId>proxies-keycloak-mapper</artifactId>
	<packaging>jar</packaging>
	<name>proxies-keycloak-mapper</name>
	<description>Keycloak mapper to add "proxies" private claim to tokens</description>

	<properties>
		<keycloak.version>17.0.1</keycloak.version>
	</properties>

	<dependencies>
		<dependency>
			<groupId>com.c4-soft.howto.user-proxies</groupId>
			<artifactId>dtos</artifactId>
		</dependency>

		<!-- provided keycloak dependencies -->
		<dependency>
			<groupId>org.keycloak</groupId>
			<artifactId>keycloak-server-spi</artifactId>
			<version>${keycloak.version}</version>
			<scope>provided</scope>
		</dependency>
		<dependency>
			<groupId>org.keycloak</groupId>
			<artifactId>keycloak-server-spi-private</artifactId>
			<version>${keycloak.version}</version>
			<scope>provided</scope>
		</dependency>
		<dependency>
			<groupId>org.keycloak</groupId>
			<artifactId>keycloak-services</artifactId>
			<version>${keycloak.version}</version>
			<scope>provided</scope>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-webflux</artifactId>
			<exclusions>
				<exclusion>
					<groupId>ch.qos.logback</groupId>
					<artifactId>logback-classic</artifactId>
				</exclusion>
			</exclusions>
		</dependency>

		<dependency>
			<groupId>org.projectlombok</groupId>
			<artifactId>lombok</artifactId>
			<optional>true</optional>
		</dependency>
	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.apache.maven.plugins</groupId>
				<artifactId>maven-shade-plugin</artifactId>
				<executions>
					<!-- Run shade goal on package phase -->
					<execution>
						<phase>package</phase>
						<goals>
							<goal>shade</goal>
						</goals>
					</execution>
				</executions>
			</plugin>
		</plugins>
	</build>
</project>
```
Two resources are required:
- `META-INF/jboss-deployment-structure.xml`
```xml
<jboss-deployment-structure>
    <deployment>
        <dependencies>
            <module name="org.keycloak.keycloak-services" />
        </dependencies>
    </deployment>
</jboss-deployment-structure>
```
- `META-INF/services/org.keycloak.protocol.ProtocolMapper`
```
com.c4_soft.howto.keycloak.ProxiesMapper
```
Last, the mapper itself. We'll use `AbstractOIDCProtocolMapper` as base class, implementing following:
- `OIDCAccessTokenMapper`
- `OIDCIDTokenMapper`
- `UserInfoTokenMapper`

Here is how it works: when a user is to be granted with a token, the mapper will query `/users/{subject}/proxies/granted` to retrieve the proxies he was griven.

To be able to access this secured endpoint, it must get an access-token (from Keycloak, as `proxies-mapper`, using client credentials flow) before first request to users service and each time access-token has expired.

```java
public class ProxiesMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
	private static final String AUTHORIZATION_SERVER_BASE_URI = "proxies-service.users-endpoint-uri";
	private static final String PROXIES_SERVICE_CLIENT_SECRET = "proxies-service.client-secret";
	private static final String PROXIES_SERVICE_CLIENT_NAME = "proxies-service.client-name";
	private static final String PROVIDER_ID = "c4-soft.com";
	private static final String PROXIES_SERVICE_BASE_URI = "proxies-service.authorization-uri";
	private static Logger logger = Logger.getLogger(ProxiesMapper.class);

	private final List<ProviderConfigProperty> configProperties = new ArrayList<>();

	private final Map<String, WebClient> webClientByBaseUri = new HashMap<>();
	private long expiresAt = 0L;
	private Optional<TokenResponseDto> token = Optional.empty();

	public ProxiesMapper() {
		ProviderConfigProperty property;

		property = new ProviderConfigProperty();
		property.setName(PROXIES_SERVICE_BASE_URI);
		property.setLabel("Proxies service base URI");
		property.setHelpText("Base URI for REST service to fetch proxies from");
		property.setType(ProviderConfigProperty.STRING_TYPE);
		property.setDefaultValue("https://bravo-ch4mp:4204/users");
		configProperties.add(property);

		property = new ProviderConfigProperty();
		property.setName(PROXIES_SERVICE_CLIENT_NAME);
		property.setLabel("Proxies mapper client-name");
		property.setHelpText("Proxies mapper client-name");
		property.setType(ProviderConfigProperty.STRING_TYPE);
		property.setDefaultValue("proxies-mapper");
		configProperties.add(property);

		property = new ProviderConfigProperty();
		property.setName(PROXIES_SERVICE_CLIENT_SECRET);
		property.setLabel("Proxies mapper client-secret");
		property.setHelpText("Proxies mapper client-secret");
		property.setType(ProviderConfigProperty.STRING_TYPE);
		configProperties.add(property);

		property = new ProviderConfigProperty();
		property.setName(AUTHORIZATION_SERVER_BASE_URI);
		property.setLabel("Authorization endpoint");
		property.setHelpText("Token end-point for authorizing proxies mapper");
		property.setType(ProviderConfigProperty.STRING_TYPE);
		property.setDefaultValue("https://bravo-ch4mp:9443/auth/realms/master");
		configProperties.add(property);
	}

	@Override
	public IDToken transformIDToken(
			IDToken token,
			ProtocolMapperModel mappingModel,
			KeycloakSession session,
			UserSessionModel userSession,
			ClientSessionContext clientSession) {
		final var proxies = getGrantsByProxiedUserSubject(mappingModel, token);
		token.getOtherClaims().put("proxies", proxies);
		setClaim(token, mappingModel, userSession, session, clientSession);
		return token;
	}

	@Override
	public AccessToken transformAccessToken(
			AccessToken token,
			ProtocolMapperModel mappingModel,
			KeycloakSession keycloakSession,
			UserSessionModel userSession,
			ClientSessionContext clientSessionCtx) {
		return (AccessToken) transformIDToken(token, mappingModel, keycloakSession, userSession, clientSessionCtx);
	}

	@Override
	public AccessToken transformUserInfoToken(
			AccessToken token,
			ProtocolMapperModel mappingModel,
			KeycloakSession keycloakSession,
			UserSessionModel userSession,
			ClientSessionContext clientSessionCtx) {
		return (AccessToken) transformIDToken(token, mappingModel, keycloakSession, userSession, clientSessionCtx);
	}

	@Override
	public String getDisplayCategory() {
		return TOKEN_MAPPER_CATEGORY;
	}

	@Override
	public String getDisplayType() {
		return "User proxies mapper";
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getHelpText() {
		return "Adds a \"proxies\" private claim containing a map of authorizations the user has to act on behalf of other users (one collection of grant IDs per user subject)";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}

	private WebClient getWebClient(ProtocolMapperModel mappingModel) {
		final var baseUri = mappingModel.getConfig().get(PROXIES_SERVICE_BASE_URI);
		return webClientByBaseUri.computeIfAbsent(baseUri, (String k) -> WebClient.builder().baseUrl(baseUri).build());
	}

	private Map<String, List<String>> getGrantsByProxiedUserSubject(ProtocolMapperModel mappingModel, IDToken token) {
		try {
			final Optional<ProxyDto[]> dtos =
					Optional.ofNullable(getWebClient(mappingModel).get().uri("/{userSubject}/proxies/granted", token.getSubject()).headers(headers -> {
						headers.setBearerAuth(getClientAuthorizationBearer(mappingModel));
					}).retrieve().bodyToMono(ProxyDto[].class).block());

			return dtos.map(Stream::of).map(s -> s.collect(Collectors.toMap(ProxyDto::getGrantingUserSubject, ProxyDto::getGrants))).orElse(Map.of());
		} catch (final WebClientResponseException e) {
			logger.warn("Failed to fetch user proxies", e);
			return Map.of();
		}
	}

	private String getClientAuthorizationBearer(ProtocolMapperModel mappingModel) {
		final var now = new Date().getTime();
		if (expiresAt < now) {
			token = Optional.ofNullable(WebClient.builder().baseUrl(mappingModel.getConfig().get(AUTHORIZATION_SERVER_BASE_URI)).defaultHeaders(headers -> {
				headers.setBasicAuth(mappingModel.getConfig().get(PROXIES_SERVICE_CLIENT_NAME), mappingModel.getConfig().get(PROXIES_SERVICE_CLIENT_SECRET));
				headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			})
					.build()
					.post()
					.uri("/protocol/openid-connect/token")
					.body(BodyInserters.fromFormData("scope", "openid").with("grant_type", "client_credentials"))
					.retrieve()
					.bodyToMono(TokenResponseDto.class)
					.block());
			expiresAt = now + 1000L * token.map(TokenResponseDto::getExpiresIn).orElse(0L);
		}
		return token.map(TokenResponseDto::getAccessToken).orElse(null);
	}
}
```

### Deploy mapper
- run `mvn package` to generate jars
- copy shaded jar to Keycloak deployments folder (i.e. `standalone\deployments` in a local instance)
- configure the client your UI uses with this new mapper (Mappers -> Create -> User proxies mapper) using the secret from `proxies-mapper` client (in Credentials tab)
