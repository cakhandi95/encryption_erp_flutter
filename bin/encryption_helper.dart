import 'dart:convert';
import 'package:crypto/crypto.dart' as crypto;
import 'package:encrypt/encrypt.dart' as encrypt;

///
/// Created by Handy on 25/07/2022
/// HP Probook G1 430.
/// Email : it.handy@borwita.co.id
///

class EncryptionHelper {

  static final String initVector = "new_erp_bcp_iv";
  static final String sKey = "new_erp_bcp_key";

  static String hashSHA256 (String input) {
    var bytes = utf8.encode(input);
    print('SHA256 - 1: $bytes');
    var sha256Result = crypto.sha256.convert(bytes);
    print('SHA256 - 2: $sha256Result');
    return sha256Result.toString();
  }

  static String? decryptBarcode(String encryptedString) {
    try {
      /// pad the encrypted base64 string with '=' characters until length matches a multiple of 4
      final int toPad = encryptedString.length % 4;
      if (toPad != 0) {
        encryptedString = encryptedString.padRight(encryptedString.length + toPad, "=");
      }

      /// get first 16 bytes which is the initialization vector
      print('hashSHA256 - initVector : ${hashSHA256(initVector)}');
      final iv = encrypt.IV.fromUtf8(hashSHA256(initVector).substring(0, 16));
      final key = encrypt.Key.fromUtf8(hashSHA256(sKey).substring(0, 16));

      print('decryptBarcode - Step 01: ${iv.bytes}');
      print('decryptBarcode - Step 02: ${iv.bytes.toString()}');

      // get cipher bytes (without initialization vector)
      print('decryptBarcode - Step 03 - hashSHA256: ${hashSHA256(sKey)}');
      print('decryptBarcode - Step 03 - hashSHA256=2: ${hashSHA256(sKey).substring(0,16)}');
      print('decryptBarcode - Step 03 - hashSHA256=3: ${utf8.encode(hashSHA256(sKey).substring(0,16))}');

      final encrypter = encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.cbc,padding: 'PKCS7'));

      final decrypted3 = encrypter.decrypt(encrypt.Encrypted.from64(encryptedString), iv: iv);

      return decrypted3;
    } catch (e) {
      print('Something Wrong : $e');
      return null;
    }
  }

  static String? generateToken(String keyword, int cmd) {
    String result = "",username="";
    if (keyword.contains("~") && keyword.isNotEmpty){
      // TODO 2 USERNAME ERP
      switch (cmd){
        case 1 : {
          result = keyword.split("~")[0];
          print("dataLog7 - getUser 1: " + result);
          break;
        }
        case 2 : {
          username = keyword.split("~")[0];
          print("dataLog8 - getUser 2: " + username);
          result = keyword.split("~")[1];
          print("dataLog9 - getUser 2: "+ result);
          String tgl = "";
          String jam = "";
          if (result.length == 12){
            tgl = result.substring(0,6);
            print("dataLog10-getUser 2: "+ tgl);
            tgl = tgl.substring(4,6)+""+tgl.substring(2,4)+""+tgl.substring(0,2);
            print("dataLog11-getUser 2: "+ tgl);
            jam = result.substring(6, result.length);
            print("dataLog12-getUser 2: "+ jam);
            jam = jam.substring(4,6)+""+jam.substring(2,4)+""+jam.substring(0,2);
            print("dataLog13-getUser 2: "+ jam);
            int sumDateTime = int.parse(tgl)+int.parse(jam);
            print("dataLog14-getUser 2: $sumDateTime ");
            String usernameASCII = "";
            List<String> arrUsername = username.toUpperCase().split("");
            int sumUsernameASCII = 0;
            String rightASCII = "";

            for (int i = 0; i < username.length ; i++) {
              print('usernameASCII - Step ${i}: ${usernameASCII}');
              print('usernameASCII: ${username.toUpperCase().codeUnitAt(i)}');
              usernameASCII = "$usernameASCII${username.toUpperCase().codeUnitAt(i)}";
              sumUsernameASCII += username.toUpperCase().codeUnitAt(i);
            }

            print("dataLogASCII-usernameASCII : "+ usernameASCII);

            // TODO HANDY 11/01/2021 : Rollback logic userNameASCII 12/05/2020
            if (usernameASCII.length <= 6) {
              rightASCII = usernameASCII;
            } else {
              rightASCII = usernameASCII.substring(usernameASCII.length - 6,usernameASCII.length);
            }

            print("dataLogASCII-rightASCII: "+rightASCII);

            double ASCIITgl = double.parse(rightASCII) * double.parse('${sumDateTime.toDouble()}');

            print("dataLogASCII-ASCIITgl: $ASCIITgl");

            double rawToken = sumUsernameASCII*ASCIITgl;

            print("dataLogASCII-rawToken: $rawToken");

            String token = rawToken.toString().substring(5,9);
            print("dataLogASCII-getUser 2: "+ token);
            result = token;
          }
          break;
        }
        default : {
          break;
        }
      }
    }
    return result;
  }

}