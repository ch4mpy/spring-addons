import 'package:BFF_Flutter_UI/bff_demo_home_page.dart';
import 'package:BFF_Flutter_UI/src/network.service.dart';
import 'package:BFF_Flutter_UI/user.model.dart';
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:http/http.dart' as http;
import 'package:provider/provider.dart';

void main() {
  runApp(ChangeNotifierProvider(
    create: (context) => UserModel(),
    child: const BffDemoApp(),
  ));
}

Future<http.Response> _forwardAuthorizationCode(Uri uri, UserModel user) async {
  final forwardUri = Uri(
      scheme: bffScheme,
      host: bffHost,
      port: bffPort,
      path: uri.path,
      queryParameters: uri.queryParameters);

  final response = await httpClient.get(forwardUri,
      headers: NetworkService.mobileOAuth2Headers());

  user.refresh();
  return response;
}

final _router = GoRouter(
  routes: [
    GoRoute(
      path: '/',
      builder: (BuildContext context, GoRouterState state) {
        return const BffDemoHomePage();
      },
      routes: <RouteBase>[
        GoRoute(
          path: 'login/oauth2/code/quiz-bff',
          builder: (BuildContext context, GoRouterState state) {
            return Consumer<UserModel>(builder: (context, user, child) {
              return FutureBuilder<http.Response>(
                  future: _forwardAuthorizationCode(state.uri, user),
                  builder: (BuildContext context,
                      AsyncSnapshot<http.Response> response) {
                    return const BffDemoHomePage();
                  });
            });
          },
        ),
        GoRoute(
          path: 'ui',
          builder: (BuildContext context, GoRouterState state) {
            return const BffDemoHomePage();
          },
        ),
      ],
    ),
  ],
);

class BffDemoApp extends StatelessWidget {
  const BffDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp.router(
      routerConfig: _router,
      title: 'BFF Demo With Flutter Frontend',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
    );
  }
}
