import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:bip32/bip32.dart' as bip32;
import 'package:crypto/crypto.dart';
import 'package:bech32/bech32.dart';
import 'package:base_x/base_x.dart';

class WalletService {
  final BaseXCodec base58 = BaseXCodec('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');

  // Generate a valid private key, but don't return it. Only use it internally.
  String generateWallet() {
    // Step 1: Create a random seed for the private key
    final seed = List<int>.generate(32, (i) => Random.secure().nextInt(256));

    // Step 2: Generate the root BIP32 node from the seed
    final root = bip32.BIP32.fromSeed(Uint8List.fromList(seed));
    
    // Step 3: Derive the first child private key from the root node
    final child = root.derivePath('m/0/0');
    
    // Step 4: Generate the Public Address from the Private Key
    final publicKey = generateAddressFromPrivateKey(child.privateKey!);

    // Return the Public Address
    return publicKey;
  }

  // Generate public address from private key
  String generateAddressFromPrivateKey(Uint8List privateKey) {
    try {
      final node = bip32.BIP32.fromPrivateKey(privateKey, Uint8List(32));
      final pubKey = node.publicKey;
      final pubKeyHash = _pubKeyToP2WPKH(pubKey);
      return _encodeBech32Address('bs', 0, pubKeyHash); // Bech32 format address
    } catch (e) {
      return "Error generating address";
    }
  }

  // Convert public key to P2WPKH (Public Key Hash)
  Uint8List _pubKeyToP2WPKH(List<int> pubKey) {
    final sha256Hash = sha256.convert(pubKey).bytes;
    return RIPEMD160Digest().process(Uint8List.fromList(sha256Hash)); // P2WPKH format
  }

  // Encode address to Bech32
  String _encodeBech32Address(String hrp, int version, Uint8List program) {
    final converted = _convertBits(program, 8, 5, true);
    return const Bech32Codec().encode(Bech32(hrp, [version] + converted)); // Bech32 encode
  }

  // Convert bits for Bech32
  List<int> _convertBits(List<int> data, int from, int to, bool pad) {
    int acc = 0, bits = 0;
    final ret = <int>[];
    final maxv = (1 << to) - 1;

    for (final value in data) {
      acc = (acc << from) | value;
      bits += from;
      while (bits >= to) {
        bits -= to;
        ret.add((acc >> bits) & maxv);
      }
    }
    if (pad && bits > 0) ret.add((acc << (to - bits)) & maxv);
    return ret;
  }
}

void main() {
  final walletService = WalletService();
  String address = "";

  // Continuously generate addresses until one contains the word "dead"
  while (!address.contains('dead') && !address.contains('burn')) {
    address = walletService.generateWallet();
    print("Generated Address: $address");
  }

  print("Found an address: $address");
}
