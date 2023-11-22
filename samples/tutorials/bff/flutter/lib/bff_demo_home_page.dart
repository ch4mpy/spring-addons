import 'package:flutter/material.dart';
import 'package:BFF_Flutter_UI/user.model.dart';
import 'package:provider/provider.dart';

class BffDemoHomePage extends StatefulWidget {
  const BffDemoHomePage({super.key});

  @override
  State<BffDemoHomePage> createState() => _BffDemoHomePageState();
}

class _BffDemoHomePageState extends State<BffDemoHomePage> {
  @override
  Widget build(BuildContext context) {
    return Consumer<UserModel>(builder: (context, user, child) {
      return Scaffold(
        appBar: AppBar(
          backgroundColor: Theme.of(context).colorScheme.inversePrimary,
          title: const Text('BFF Demo With Flutter Frontend'),
          actions: user.current.isAuthenticated()
              ? [
                  FloatingActionButton(
                    onPressed: user.logout,
                    tooltip: 'Logout',
                    child: const Icon(Icons.logout),
                  )
                ]
              : user.loginOptions.map((loginOpt) => FloatingActionButton(
                    onPressed: () => user.login(loginOpt),
                    tooltip: 'Login',
                    child: const Icon(Icons.login),
                  )).toList(),
        ),
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: <Widget>[
              const Text(
                'You hare: ',
              ),
              Text(
                user.current.username,
                style: Theme.of(context).textTheme.headlineMedium,
              ),
            ],
          ),
        ), // This trailing comma makes auto-formatting nicer for build methods.
      );
    });
  }
}
