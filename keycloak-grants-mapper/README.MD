# `Grants` Mapper

Sample Keycloak mapper to retrieve user proxies (what he can do on behalf of ohter users) from a REST web-service and add it to token as private claim.

To deploy, just:
- `mvn package`
- copy produced jar to your Keycloak `deployments` directory