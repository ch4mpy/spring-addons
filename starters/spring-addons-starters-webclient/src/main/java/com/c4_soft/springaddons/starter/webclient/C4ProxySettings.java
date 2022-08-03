package com.c4_soft.springaddons.starter.webclient;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import reactor.netty.transport.ProxyProvider;

/**
 * <p>
 * Configuration for HTTP or SOCKS proxy.
 * </p>
 * <p>
 * HTTP_PROXY and NO_PROXY standard environment variable are used only if com.c4-soft.springaddons.proxy.hostname is left empty and
 * com.c4-soft.springaddons.proxy.enabled is TRUE or null.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
@Data
@Component
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.proxy")
public class C4ProxySettings {
	private Boolean enabled;
	private ProxyProvider.Proxy type = ProxyProvider.Proxy.HTTP;
	@Getter(AccessLevel.NONE)
	private Optional<String> host;
	private Integer port;
	private String username;
	private String password;
	@Getter(AccessLevel.NONE)
	private String nonProxyHostsPattern;
	private long connectTimeoutMillis = 10000;

	/* also parse standard environment variables */
	@Getter(AccessLevel.NONE)
	private Optional<URL> httpProxy;

	@Getter(AccessLevel.NONE)
	@Value("${no_proxy:#{T(java.util.List).of()}}")
	private List<String> noProxy = List.of();

	@Value("${com.c4-soft.springaddons.proxy.host:#{null}}")
	public void setHost(String host) {
		this.host = StringUtils.hasText(host) ? Optional.of(host) : Optional.empty();
	}

	@Value("${http_proxy:#{null}}")
	public void setHttpProxy(String url) throws MalformedURLException {
		this.httpProxy = StringUtils.hasText(url) ? Optional.of(new URL(url)) : Optional.empty();
	}

	public String getHostname() {
		if (Boolean.FALSE.equals(enabled)) {
			return null;
		}
		return host.orElse(httpProxy.map(URL::getHost).orElse(null));
	}

	public ProxyProvider.Proxy getType() {
		if (Boolean.FALSE.equals(enabled)) {
			return null;
		}
		return host.map(h -> type).orElse(httpProxy.map(URL::getProtocol).map(C4ProxySettings::getProtocoleType).orElse(null));
	}

	public Integer getPort() {
		if (Boolean.FALSE.equals(enabled)) {
			return null;
		}
		return host.map(h -> port).orElse(httpProxy.map(URL::getPort).orElse(null));
	}

	public String getUsername() {
		if (Boolean.FALSE.equals(enabled)) {
			return null;
		}
		return host.map(h -> username).orElse(httpProxy.map(URL::getUserInfo).map(C4ProxySettings::getUserinfoName).orElse(null));
	}

	public String getPassword() {
		if (Boolean.FALSE.equals(enabled)) {
			return null;
		}
		return host.map(h -> password).orElse(httpProxy.map(URL::getUserInfo).map(C4ProxySettings::getUserinfoPassword).orElse(null));
	}

	public String getNoProxy() {
		if (Boolean.FALSE.equals(enabled)) {
			return null;
		}
		return host.map(h -> nonProxyHostsPattern).orElse(getNonProxyHostsPattern(noProxy));
	}

	static ProxyProvider.Proxy getProtocoleType(String protocol) {
		if (protocol == null) {
			return null;
		}
		final var lower = protocol.toLowerCase();
		if (lower.startsWith("http")) {
			return ProxyProvider.Proxy.HTTP;
		}
		if (lower.startsWith("socks4")) {
			return ProxyProvider.Proxy.SOCKS4;
		}
		return ProxyProvider.Proxy.SOCKS5;
	}

	static String getUserinfoName(String userinfo) {
		if (userinfo == null) {
			return null;
		}
		return userinfo.split(":")[0];
	}

	static String getUserinfoPassword(String userinfo) {
		if (userinfo == null) {
			return null;
		}
		final var splits = userinfo.split(":");
		return splits.length < 2 ? null : splits[1];
	}

	static String getNonProxyHostsPattern(List<String> noProxy) {
		if (noProxy == null || noProxy.isEmpty()) {
			return null;
		}
		return noProxy
				.stream()
				.map(host -> host.replace(".", "\\."))
				.map(host -> host.replace("-", "\\-"))
				.map(host -> host.startsWith("\\.") ? ".*" + host : host)
				.collect(Collectors.joining(")|(", "(", ")"));
	}
}
