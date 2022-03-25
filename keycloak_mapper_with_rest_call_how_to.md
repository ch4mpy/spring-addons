# How to build a Keycloak mapper to add a private-claim with data from a web-service

Let's say we have a security model where users can grant some of their authorizations to some other users of their choice.

To implement this, we'll proceed in two steps:
- create a RESTful Spring micro-service to CRUD grants between users
- create a Keycloak "mapper" calling this service to add a `proxies` private-claim to tokens

## Spring resource-server for proxies between users

### Domain model
- "grants" will be simple strings like `READ_A` or `EDIT_B`
- users will be identified by e-mail. Any other unique non-null key like subject or preferred-username could have been chosen.
- a "Proxy" holds the "grants" a `proxiedUser` provides a `grantedUser` with:
``` java
@XmlRootElement
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProxyDto implements Serializable {
	private static final long serialVersionUID = 7382907575214377114L;

	@NotEmpty
	@NotNull
	private String proxiedUserEmail;

	@NotEmpty
	@NotNull
	private String grantedUserEmail;

	@NotNull
	private List<String> grants;
}
```

### Initiate project
- create project structure using maven archetype:
``` bash
mvn archetype:generate \
  -DarchetypeCatalog=remote \
  -DarchetypeGroupId=com.c4-soft.springaddons \
  -DarchetypeArtifactId=spring-webmvc-archetype \
  -DarchetypeVersion=4.1.6 \
  -DgroupId=com.c4-soft.howto \
  -DartifactId=user-proxies \
  -Dversion=1.0.0-SNAPSHOT \
  -Dapi-artifactId=proxies-api \
  -Dapi-path=user-proxies
```
- replace DTOs with the `ProxyDto` defined earlier
- replace domain entity with those two:
``` java
@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
	@Id
	@GeneratedValue
	private Long id;

	@Column(nullable = false, unique = true)
	private String subject;

	@Column(nullable = false, unique = true)
	private String email;

	@Column(nullable = false, unique = true)
	private String preferredUsername;
}
```
``` java
@Entity
@Table(name = "user_proxies")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Proxy {
	@NotNull
	@ManyToOne(optional = false, cascade = CascadeType.ALL, fetch = FetchType.EAGER)
	@JoinColumn(updatable = false, nullable = false)
	private User proxiedUser;

	@NotEmpty
	@ManyToOne(optional = false, cascade = CascadeType.ALL, fetch = FetchType.EAGER)
	@JoinColumn(updatable = false, nullable = false)
	private User grantedUser;

	@NotNull
	@ElementCollection(fetch = FetchType.EAGER)
	private List<String> grants;
}
```
- Replace the JPA repository with one to CRUD proxies:
``` java
public interface ProxyRepository extends JpaRepository<Proxy, Long> {
	
    List<Proxy> findByProxiedUserEmail(String email);
    
}
```
- Replace DTO <-> domain mapper with:
``` java
@Mapper(componentModel = ComponentModel.SPRING)
public interface UserProxyMapper {

	@Mapping(target = "proxiedUserEmail", source = "proxiedUser.email")
	@Mapping(target = "grantedUserEmail", source = "grantedUser.email")
	ProxyDto toDto(Proxy domain);

}
```
And now a `@RestController` for proxy resources with following specs:
- create unknown user entries in proxies database (this DB is referential for proxies, not users)
- end-points for CRUD (respectively POST, GET, PUT and DELETE operations) with path `/user-proxies/{proxiedUserSubject}`
- readonly end-points should be accessible to anonymous, others follow this rules
  - identifed users can edit (POST, PUT, DELETE) their own proxies (current user subject is equal to proxiedUserSubject path variable
  - users with `PROXIES_ADMIN` authority can edit any user proxies
  - users with a proxy containing `EDIT_PROXIES` grant for current user can edit