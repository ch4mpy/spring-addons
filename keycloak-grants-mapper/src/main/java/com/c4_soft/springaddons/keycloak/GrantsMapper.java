package com.c4_soft.springaddons.keycloak;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.springframework.web.reactive.function.client.WebClient;

import com.c4_soft.springaddons.samples.webmvc.web.UserProxiesDto;

public class GrantsMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
	private static final String PROVIDER_ID = "c4-soft.com";
	private static final String GRANTS_SERVICE_BASE_URI = "grants-service.base-uri";
	private static Logger logger = Logger.getLogger(GrantsMapper.class);

	private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
	static {
		ProviderConfigProperty property;
		property = new ProviderConfigProperty();
		property.setName(GRANTS_SERVICE_BASE_URI);
		property.setLabel("Grants service base URI");
		property.setHelpText("Base URI for REST service to fetch grants from");
		property.setType(ProviderConfigProperty.STRING_TYPE);
		property.setDefaultValue("https://localhost:5443");
		configProperties.add(property);
	}

	private final Map<String, WebClient> webClientByBaseUri = new HashMap<>();

	@Override
	public String getDisplayCategory() {
		return TOKEN_MAPPER_CATEGORY;
	}

	@Override
	public String getDisplayType() {
		return "Grants mapper";
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getHelpText() {
		return "Adds a \"grants\" private claim containing a map of authorizations the user has to act on behalf of other users (one collection per user subject)";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}

	@Override
	public AccessToken transformAccessToken(
			AccessToken token,
			ProtocolMapperModel mappingModel,
			KeycloakSession keycloakSession,
			UserSessionModel userSession,
			ClientSessionContext clientSessionCtx) {
		logger.info(String.format("Request user proxies at URI: %s/grants/%s", mappingModel.getConfig().get(GRANTS_SERVICE_BASE_URI), token.getSubject()));
		token
				.getOtherClaims()
				.put(
						"grants",
						getWebClient(mappingModel)
								.get()
								.uri("/grants/{userSubject}", token.getSubject())
								.retrieve()
								.bodyToMono(UserProxiesDto.class)
								.map(UserProxiesDto::getGrantsByProxiedUserSubject)
								.block());
		setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);
		return token;
	}

	public static ProtocolMapperModel create() {
		final ProtocolMapperModel mapper = new ProtocolMapperModel();
		mapper.setProtocolMapper(PROVIDER_ID);
		mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
		final Map<String, String> config = new HashMap<>();
		config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
		config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
		config.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true");
		mapper.setConfig(config);
		return mapper;
	}

	private WebClient getWebClient(ProtocolMapperModel mappingModel) {
		final String baseUri = mappingModel.getConfig().get(GRANTS_SERVICE_BASE_URI);
		return webClientByBaseUri.computeIfAbsent(baseUri, (String k) -> WebClient.builder().baseUrl(baseUri).build());
	}
}
