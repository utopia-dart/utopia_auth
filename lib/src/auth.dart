import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart' as crypto;

class Auth {
  static String encodeSession(String id, String secret) {
    return base64Encode(utf8.encode(jsonEncode({
      'id': id,
      'secret': secret,
    })));
  }

  static Map<String, dynamic> decodeSession(String session) {
    return jsonDecode(utf8.decode(base64Decode(session)));
  }

  static String sha256(String string) {
    return crypto.sha256.convert(utf8.encode(string)).toString();
  }

  static String passwordGenerator([int length = 20]) {
    return _randomString(length);
  }

  static String tokenGenerator([int length = 128]) {
    return _randomString(length);
  }

  static dynamic tokenVerify(
      List<Map<String, dynamic>> tokens, int type, String secret) {
    for (final token in tokens) {
      if (token['expire'] != null &&
          token['type'] == type &&
          token['secret'] == sha256(secret) &&
          token['expire'] >= DateTime.now().microsecondsSinceEpoch) {
        return token['id'];
      }
    }
    return false;
  }

  static dynamic sessionVerify(
      List<Map<String, dynamic>> sessions, String secret) {
    for (final session in sessions) {
      if (session['secret'] == sha256(secret) &&
          session['provider'] != null &&
          session['expire'] >= DateTime.now().millisecondsSinceEpoch) {
        return session['id'];
      }
    }
    return false;
  }

  static String _randomString(int length) {
    String lowerCaseLetters = "abcdefghijklmnopqrstuvwxyz";
    String upperCaseLetters = lowerCaseLetters.toUpperCase();
    String numbers = "0123456789";
    String special = "@#=+!£\$%&?[](){}";
    String allowedChars = "";
    allowedChars += lowerCaseLetters;
    allowedChars += upperCaseLetters;
    allowedChars += numbers;
    allowedChars += special;

    int i = 0;
    String result = "";
    while (i < length.round()) {
      int randomInt = Random.secure().nextInt(allowedChars.length);
      result += allowedChars[randomInt];
      i++;
    }

    return result;
  }
}
