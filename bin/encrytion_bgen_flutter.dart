import 'encryption_helper.dart';

final String resultQR = 'HwSa2Tmzvkm0ztkrpheh5n3wouLs1tY8Ep+Keqm1KpY=';

void main(List<String> arguments) {
  String? result = EncryptionHelper.decryptBarcode(resultQR);
  print('value qrcode: $result');
  print('generate Token: ${EncryptionHelper.generateToken(result!, 2)}');
}
