import 'dart:developer';

import 'package:biometricx/biometricx.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:get_storage/get_storage.dart';
import 'package:provider/provider.dart';

import 'states/states.dart';
import 'widgets/widgets.dart';

main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await GetStorage.init();
  runApp(MultiProvider(
    providers: [
      ChangeNotifierProvider(create: (_) => AppState()),
      ChangeNotifierProvider(create: (_) => MessagesState()),
    ],
    child: App(),
  ));
}

class App extends StatelessWidget {
  const App({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.light,
      ),
      darkTheme: ThemeData(
        brightness: Brightness.dark,
      ),
      themeMode: ThemeMode.dark,
      home: Home(),
    );
  }
}

class Home extends StatelessWidget {
  const Home({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (_, app, __) => WillPopScope(
        onWillPop: () {
          if (app.isWrite || app.isRead) {
            app.showList();
            return Future.value(false);
          }

          return Future.value(true);
        },
        child: Scaffold(
          appBar: AppBar(
            title: Text('BiometricX'),
            centerTitle: true,
          ),
          body: Builder(
            builder: (_) {
              if (app.isWrite) return WriteMessage();
              if (app.isRead) return ReadMessage(app.currentMessage);
              return MessageList();
            },
          ),
          floatingActionButtonLocation:
              FloatingActionButtonLocation.centerFloat,
          floatingActionButton: app.isList
              ? Row(
                  children: [
                    FloatingActionButton(
                      child: Icon(Icons.add_rounded),
                      // onPressed: app.write,
                      onPressed: () async {
                        log('message');
                        var enc = await BiometricX.encrypt(
                          userAuthenticationRequired: false,
                          storeSharedPreferences: false,
                          tag: '123',
                          returnCipher: true,
                          messageKey: '123',
                          message: 'saddam',
                        );
                        log(enc.data.toString());
                      },
                    ),
                    FloatingActionButton(
                      child: Icon(Icons.mic),
                      // onPressed: app.write,
                      onPressed: () async {
                        var dec = await BiometricX.decrypt(
                          userAuthenticationRequired: false,
                          storeSharedPreferences: false,
                          tag: '1232',
                          messageKey: '1232',
                          cipherText: "50kkGZBiLdYtgam2j7Wn0uWiTs91Zg==",
                        );
                        log(dec.data.toString());
                      },
                    ),
                  ],
                )
              : null,
        ),
      ),
    );
  }
}
