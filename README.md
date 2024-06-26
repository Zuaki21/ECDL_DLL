# ECDL

学部研究「リング署名を用いた事前登録者の匿名認証方式の提案」にて作成
- ECDSAによるリング署名を行うライブラリ
- Unity/C#から呼び出して動作確認したが、他言語でも使用可
- 具体的な実装内容は["dllmain.cpp"](https://github.com/Zuaki21/ECDL_DLL/blob/main/ECDLRingDLL/ECDLRingDLL/dllmain.cpp)に実装

## 仕組み
- OpenSSLを使用
- 128ビットセキュリティに置いてECDSA鍵を使うことでRSA鍵より1/12の鍵長に短縮
- 楕円曲線暗号ECDSAは一般的なリング署名では対応しないため、"1-out-of-n Signatures from
a Variety of Keys"の離散対数によるリング署名方式を転用した
- 曲線"NID secp256k1"、ハッシュ関数"SHA-256"を使用


## 参考
- [Ronald L. Rivest, Adi Shamir, and Yael Tauman, ”How to Leak a Secret,” International Conference on the Theory and Application of Cryptology and Information Security, pp.552–565, 2001-11-20.](https://www.iacr.org/cryptodb/data/paper.php?pubkey=424)
- [Masayuki Abe, Miyako Ohkubo, Koutarou Suzuki, ”1-out-of-n Signatures from a Variety of Keys,”Advances in Cryptology ― ASIACRYPT 2002, pp.414-431, 2002-1-1](https://www.iacr.org/cryptodb/data/paper.php?pubkey=50)