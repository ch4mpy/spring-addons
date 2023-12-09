import 'dart:convert';
import 'dart:html';
import 'package:http/http.dart' as http;
import 'package:flutter/foundation.dart' show kIsWeb;

const bffScheme = 'http';
const bffHost = 'localhost';
const bffPort = 8080;
const bffUri = '$bffScheme://$bffHost:$bffPort';
final httpClient = NetworkService();

/// <h1>Helper to handle cookies, CSRF and JSON encoding</h1>
/// <p>
///   Cookies are sent back only to the server which emitted it (not to all servers from the same domain).
/// </p>
/// <p>
///   CSRF token is read from XSRF-TOKEN cookie and set as X-XSRF-TOKEN header of
///   POST, PUT and DELET requests to the server which set the cookie.
/// </p>
class NetworkService {
  /// An index of cookies by server ID (combination of host and port)
  final List<Cookie> _cookies = [];

  /*------------------*/
  /* Public interface */
  /*------------------*/
  Future<http.Response> head(Uri uri, {Map<String, String>? headers}) {
    return http
        .head(uri, headers: _headersWithCookies(uri, headers))
        .then((r) => _updateStoredCookies(uri, r));
  }

  Future<http.Response> get(Uri uri, {Map<String, String>? headers}) {
    return http
        .get(uri, headers: _headersWithCookies(uri, headers))
        .then((r) => _updateStoredCookies(uri, r));
  }

  Future<http.Response> post(Uri uri,
      {Map<String, String>? headers, Object? body, Encoding? encoding}) {
    return http
        .post(uri,
            headers: _headersWithCsrf(uri, _headersWithCookies(uri, headers)),
            body: body,
            encoding: encoding)
        .then((r) => _updateStoredCookies(uri, r));
  }

  Future<http.Response> put(Uri uri, {headers, body, encoding}) {
    return http
        .put(uri,
            headers: _headersWithCsrf(uri, _headersWithCookies(uri, headers)),
            body: body,
            encoding: encoding)
        .then((r) => _updateStoredCookies(uri, r));
  }

  Future<http.Response> patch(Uri uri, {headers, body, encoding}) {
    return http
        .patch(uri,
            headers: _headersWithCsrf(uri, _headersWithCookies(uri, headers)),
            body: body,
            encoding: encoding)
        .then((r) => _updateStoredCookies(uri, r));
  }

  Future<http.Response> delete(Uri uri, {headers, body, encoding}) {
    return http
        .delete(uri,
            headers: _headersWithCsrf(uri, _headersWithCookies(uri, headers)),
            body: body,
            encoding: encoding)
        .then((r) => _updateStoredCookies(uri, r));
  }

  /// Set a header to ask the BFF to answer in the 2xx range instead of a 302
  static Map<String, String> mobileOAuth2Headers(
      {Map<String, String>? headers}) {
    final mobileOAuth2Headers = headers ?? <String, String>{};
    mobileOAuth2Headers['X-RESPONSE-STATUS'] = 'NO_CONTENT';
    return mobileOAuth2Headers;
  }

  /*-----------*/
  /* Internals */
  /*-----------*/
  Map<String, String> _headersWithCookies(
      Uri request, Map<String, String>? headers) {
    final headersWithCookies = headers ?? <String, String>{};
    const isMobile = !kIsWeb;
    if (isMobile) {
      final now = DateTime.now();
      _cookies
          .removeWhere((element) => element.expires?.isBefore(now) ?? false);

      final domainCookies = _cookies.where((c) => c.isToBeAttachedTo(request));
      if (domainCookies.isNotEmpty) {
        headersWithCookies['Cookie'] =
            domainCookies.map((e) => '${e.key}=${e.value}').join("; ");
      }
    }

    return headersWithCookies;
  }

  Map<String, String> _headersWithCsrf(
      Uri request, Map<String, String>? headers) {
    final headersWithCsrf = headers ?? <String, String>{};
    final domainCookies = _cookies
        .where((c) => c.isToBeAttachedTo(request) && c.key == 'XSRF-TOKEN');
    if (domainCookies.isNotEmpty) {
      headersWithCsrf['X-XSRF-TOKEN'] = domainCookies.first.value;
    }
    return headersWithCsrf;
  }

  http.Response _updateStoredCookies(Uri requestUri, http.Response response) {
    final setCookie = response.headers['set-cookie'];
    final cookies = document.cookie;
    if (setCookie?.isNotEmpty ?? false) {
      final cookies = Cookie.fromSetCookieHeader(requestUri, setCookie!);
      final cookieKeys = cookies.map((e) => e.key);
      _cookies.removeWhere((element) => cookieKeys.contains(element.key));
      _cookies.addAll(cookies);
    }
    return response;
  }
}

class Cookie {
  final String? domain;
  final String authority;
  final String path;
  final bool secure;
  final String key;
  final String value;
  final DateTime? expires;

  Cookie(
      {required this.domain,
      required this.authority,
      required this.path,
      required this.secure,
      required this.key,
      required this.value,
      required this.expires});

  bool isToBeAttachedTo(Uri request) {
    if (secure && request.scheme != 'https') {
      return false;
    }
    return (domain?.isNotEmpty ?? false)
        ? request.host.endsWith(domain!)
        : _authority(request.host, request.port) == authority;
  }

  static Iterable<Cookie> fromSetCookieHeader(
      Uri requestUri, String setCookie) {
    final exploded =
        setCookie.split(';').map((e) => e.trim()).map((e) => e.split('='));
    final attributes = {
      for (var e in exploded) e[0].trim(): e.length > 1 ? e[1] : null
    };
    final path = attributes['path'] ?? '/';
    final expiresStr = attributes['expires'] ?? '';
    final expires = expiresStr.isNotEmpty ? DateTime.parse(expiresStr) : null;
    return attributes.entries
        .where((e) => !['EXPIRES', 'PATH', 'SECURE', 'HTTPONLY', 'SAMESITE']
            .contains(e.key.toUpperCase()))
        .map((e) => Cookie(
            domain: attributes['domain'],
            authority: _authority(requestUri.host, requestUri.port),
            path: path,
            secure: 'https' == requestUri.scheme,
            key: e.key,
            value: e.value ?? '',
            expires: expires));
  }

  static _authority(String host, int port) {
    return '$host:$port';
  }
}
