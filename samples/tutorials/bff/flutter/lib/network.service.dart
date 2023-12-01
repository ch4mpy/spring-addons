import 'dart:convert';
import 'dart:io';

import 'package:quiver/collection.dart';

const bffScheme = 'https';
const bffHost = 'quiz.c4-soft.com';
const bffPort = 443;
const bffUri = '$bffScheme://$bffHost:$bffPort';
final httpClient = NetworkService();


class Response {
  final int status;
  final dynamic body;
  final String? error;

  Response(this.status, this.body, this.error);
}

abstract class HttpClientFacade {
  Response get(Uri uri, {Multimap<String, String>? headers});

  Response getJson(Uri uri, {Multimap<String, String>? headers});

  Response post(Uri uri, dynamic body, {Multimap<String, String>? headers});

  Response postAsJson(Uri uri, dynamic body, {Multimap<String, String>? headers});

  Response put(Uri uri, dynamic body, {Multimap<String, String>? headers});

  Response putAsJson(Uri uri, dynamic body, {Multimap<String, String>? headers});

  Response delete(Uri uri, {Multimap<String, String>? headers});
}

class MobileHttpClientFacade extends HttpClientFacade {
  @override
  Response delete(Uri uri, {Multimap<String, String>? headers}) {
    // TODO: implement delete
    throw UnimplementedError();
  }

  @override
  Response get(Uri uri, {Multimap<String, String>? headers}) {
    // TODO: implement get
    throw UnimplementedError();
  }

  @override
  Response getJson(Uri uri, {Multimap<String, String>? headers}) {
    // TODO: implement getJson
    throw UnimplementedError();
  }

  @override
  Response post(Uri uri, body, {Multimap<String, String>? headers}) {
    // TODO: implement post
    throw UnimplementedError();
  }

  @override
  Response postAsJson(Uri uri, body, {Multimap<String, String>? headers}) {
    // TODO: implement postAsJson
    throw UnimplementedError();
  }

  @override
  Response put(Uri uri, body, {Multimap<String, String>? headers}) {
    // TODO: implement put
    throw UnimplementedError();
  }

  @override
  Response putAsJson(Uri uri, body, {Multimap<String, String>? headers}) {
    // TODO: implement putAsJson
    throw UnimplementedError();
  }

}

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
  final Map<String, List<Cookie>> _cookies = {};
  final HttpClient _client = HttpClient();
  final _encoder = const JsonEncoder();

  static Multimap<String, String> mobileOAuth2Headers() {
    final mobileOAuth2Headers = Multimap<String, String>();
    mobileOAuth2Headers.add('X-RESPONSE-STATUS', 'NO_CONTENT');
    return mobileOAuth2Headers;
  }

  /*------------------*/
  /* Public interface */
  /*------------------*/
  Future<HttpClientResponse> get(Uri uri,
      {Multimap<String, String>? headers}) async {
    final request = await _client.getUrl(uri);
    headers?.forEach((name, value) {
      request.headers.add(name, value);
    });

    _addStoredCookies(request);

    final response = await request.close();

    _updateStoredCookies(response, _serverId(request));

    return response;
  }

  Future<Response> getJson(Uri uri,
      {Multimap<String, String>? headers}) async {
    final Multimap<String, String> headersWithAccept =
        headers ?? Multimap<String, String>();
    headersWithAccept.removeAll(HttpHeaders.acceptHeader);
    headersWithAccept.removeAll(HttpHeaders.acceptCharsetHeader);
    headersWithAccept.add(HttpHeaders.acceptHeader, 'application/json');
    headersWithAccept.add(HttpHeaders.acceptCharsetHeader, 'utf-8');

    final response = await get(uri, headers: headersWithAccept);
    final stringData = await response.transform(utf8.decoder).join();
    if (response.statusCode < 200 || response.statusCode > 299) {
      return Response(response.statusCode, null, stringData);
    }
    return Response(response.statusCode, jsonDecode(stringData), null);
  }

  Future<HttpClientResponse> post(Uri uri,
      {Multimap<String, String>? headers, body}) async {
    final request = await _client.postUrl(uri);
    return _sendStateChangingRequest(request, headers, body);
  }

  Future<HttpClientResponse> postJson(Uri uri, dynamic body,
      {Multimap<String, String>? headers}) async {
    return post(uri,
        headers: _withJsonContentType(headers), body: _encoder.convert(body));
  }

  Future<HttpClientResponse> put(Uri uri, {headers, body, encoding}) async {
    final request = await _client.putUrl(uri);
    return _sendStateChangingRequest(request, headers, body);
  }

  Future<HttpClientResponse> putJson(Uri uri, dynamic body,
      {Multimap<String, String>? headers}) async {
    return put(uri,
        headers: _withJsonContentType(headers), body: _encoder.convert(body));
  }

  Future<HttpClientResponse> delete(Uri uri, {headers}) async {
    final request = await _client.deleteUrl(uri);
    return _sendStateChangingRequest(request, headers, null);
  }

  /*-----------*/
  /* Internals */
  /*-----------*/
  String _serverId(HttpClientRequest request) {
    return '${request.uri.host}:${request.uri.port}';
  }

  void _updateStoredCookies(HttpClientResponse response, String serverId) {
    final cookies = response.cookies;
    final now = DateTime.now();

    for (final cookie in cookies) {
      final domainCookies = _cookies[serverId] ?? [];
      domainCookies.removeWhere((element) =>
          now.isAfter(cookie.expires ?? now) ||
          (cookie.name == element.name &&
              (cookie.path ?? '') == (element.path ?? '')));
      domainCookies.add(cookie);
      _cookies[serverId] = domainCookies;
    }
  }

  void _addStoredCookies(HttpClientRequest request) {
    final cookies = _cookies[_serverId(request)] ?? [];
    final now = DateTime.now();
    cookies.removeWhere((element) => now.isAfter(element.expires ?? now));
    cookies
        .where((element) =>
            element.path == null ||
            request.uri.path.contains(element.path ?? ''))
        .forEach((element) {
      request.cookies.add(element);
    });
  }

  void _addCsrf(String domain, HttpHeaders headers) {
    final domainCookies = _cookies[domain] ?? [];
    final csrfCookie = domainCookies.firstWhere(
        (element) => element.name == 'XSRF-TOKEN',
        orElse: () => Cookie('XSRF-TOKEN', ''));
    if (csrfCookie.value.isNotEmpty) {
      headers.add('X-XSRF-TOKEN', csrfCookie.value);
    }
  }

  Future<HttpClientResponse> _sendStateChangingRequest(
      HttpClientRequest request,
      Multimap<String, String>? headers,
      dynamic body) async {
    final serverId = _serverId(request);

    headers?.forEach((name, value) {
      request.headers.add(name, value);
    });
    _addCsrf(serverId, request.headers);

    _addStoredCookies(request);

    if (body != null) {
      request.write(body);
    }

    final response = await request.close();

    _updateStoredCookies(response, serverId);

    return response;
  }

  Multimap<String, String> _withJsonContentType(
      Multimap<String, String>? headers) {
    final Multimap<String, String> headersWithContentType =
        headers ?? Multimap<String, String>();
    headersWithContentType.removeAll(HttpHeaders.contentTypeHeader);
    headersWithContentType.add(
        HttpHeaders.contentTypeHeader, 'application/json; charset=utf-8');
    return headersWithContentType;
  }
}
