// dllmain.cpp : DLL アプリケーションのエントリ ポイントを定義します。
#include "pch.h"
#define DLLEXPORT extern "C" __declspec(dllexport)

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>#include "pch.h"

#define MESSAGE "Hello!"
#define RING_SIZE 4
#define KEY_SIZE 2048
#define HEX_UNSIGNED_SIZE 65  // null文字を含めた文字数

typedef struct ECDSAPublicKey {
	char publicKeyX[HEX_UNSIGNED_SIZE];
	char publicKeyY[HEX_UNSIGNED_SIZE];
} ECDSAPublicKey;

typedef struct ECDSAKeyPair {
	char privateKey[HEX_UNSIGNED_SIZE];
	ECDSAPublicKey publicKey;
} ECDSAKeyPair;

DLLEXPORT int __stdcall GetKeyPairString(ECDSAKeyPair* keyPair) {
	unsigned char rand_hash[SHA256_DIGEST_LENGTH];
	RAND_bytes(rand_hash, SHA256_DIGEST_LENGTH);
	BIGNUM* private_key = BN_new();
	EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	EC_POINT* public_key = EC_POINT_new(group);
	private_key = BN_bin2bn(rand_hash, SHA256_DIGEST_LENGTH, NULL);
	EC_POINT_mul(group, public_key, private_key, NULL, NULL, NULL);

	// 鍵を16進数文字列に変換して格納
	BIGNUM* x = BN_new();  // x座標
	BIGNUM* y = BN_new();  // y座標
	EC_POINT_get_affine_coordinates(group, public_key, x, y, NULL);
	strcpy_s(keyPair->publicKey.publicKeyX, sizeof(keyPair->publicKey.publicKeyX), BN_bn2hex(x));
	strcpy_s(keyPair->publicKey.publicKeyY, sizeof(keyPair->publicKey.publicKeyY), BN_bn2hex(y));
	strcpy_s(keyPair->privateKey, sizeof(keyPair->privateKey), BN_bn2hex(private_key));

	// メモリ解放
	BN_free(private_key);
	EC_POINT_free(public_key);
	BN_free(x);
	BN_free(y);
	return 0;
}


void PublicKeyToString(EC_POINT* public_key, EC_GROUP* group,
    ECDSAPublicKey* key) {
    BIGNUM* x = BN_new();  // x座標
    BIGNUM* y = BN_new();  // y座標
    EC_POINT_get_affine_coordinates(group, public_key, x, y, NULL);
    strcpy_s(key->publicKeyX, HEX_UNSIGNED_SIZE, BN_bn2hex(x));
    strcpy_s(key->publicKeyY, HEX_UNSIGNED_SIZE, BN_bn2hex(y));
    BN_free(x);
    BN_free(y);
    return;
}

void StringToPublicKey(EC_POINT* public_key, EC_GROUP* group,
    ECDSAPublicKey* key) {
    BIGNUM* x = BN_new();  // x座標
    BIGNUM* y = BN_new();  // y座標
    BN_hex2bn(&x, key->publicKeyX);
    BN_hex2bn(&y, key->publicKeyY);
    EC_POINT_set_affine_coordinates(group, public_key, x, y, NULL);
    BN_free(x);
    BN_free(y);
    return;
}

void BIGNUMToString(BIGNUM* bn, char* str) {
    strcpy_s(str, HEX_UNSIGNED_SIZE, BN_bn2hex(bn));
    return;
}

void StringToBIGNUM(BIGNUM* bn, char* str) {
    BN_hex2bn(&bn, str);
    return;
}

void GetPublicKeyStrings(ECDSAPublicKey* publicKeyStrings[], int size) {
    for (int i = 0; i < size; i++) {
        ECDSAKeyPair* keyPair = (ECDSAKeyPair*)malloc(sizeof(ECDSAKeyPair));
        if (keyPair == NULL) {
			fprintf(stderr, "Memory allocation failed\n");
			exit(EXIT_FAILURE);
		}
        GetKeyPairString(keyPair);
        // アドレスではなく、値を代入する
        publicKeyStrings[i] = &keyPair->publicKey;
    }
    return;
}

BIGNUM* H_function(char message[], EC_POINT* r_point, EC_GROUP* group) {
    // メッセージのハッシュ値を計算
    unsigned char message_hash[SHA256_DIGEST_LENGTH];

    BIGNUM* x = BN_new();  // x座標
    BIGNUM* y = BN_new();  // y座標
    EC_POINT_get_affine_coordinates(group, r_point, x, y, NULL);

    // x, y を文字列に変換
    char* hex_x = BN_bn2hex(x);
    char* hex_y = BN_bn2hex(y);

    // str = message + hex_x + hex_y (+は連結)
    size_t len = strlen(message) + 2 * BN_num_bytes(x) + 2 * BN_num_bytes(y);
    // 文字列を連結するために動的にメモリを確保
    unsigned char* str = (unsigned char*)malloc(len + 1);

    // メモリ確保に失敗した場合のエラーハンドリング
    if (str == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // 安全に文字列を構築
    // strcpy,strcatはC4996(非推奨)のため、snprintfを使用
    snprintf((char*)str, len + 1, "%s%s%s", message, hex_x, hex_y);

    // strをSHA256でハッシュしてBIGNUMに変換
    BIGNUM* c = BN_new();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(str, len, hash);
    c = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);

    // 確保したメモリを解放
    BN_free(x);
    BN_free(y);
    OPENSSL_free(hex_x);
    OPENSSL_free(hex_y);
    free(str);

    return c;
}

// 署名者の秘密鍵を使い、S_kを逆算して求める関数(α - n_k×c_k=s_k)
BIGNUM* sk_function(EC_GROUP* group, BIGNUM* alpha, BIGNUM* ck, BIGNUM* nk) {
    BIGNUM* sk = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    // n_k × c_k
    BIGNUM* nkck = BN_new();

    if (!BN_mul(nkck, nk, ck, ctx)) {
        fprintf(stderr, "Multiplication error\n");
        ERR_print_errors_fp(stderr);
    }

    // α - n_k×c_k
    if (!BN_sub(sk, alpha, nkck)) {
        fprintf(stderr, "Subtraction error\n");
        ERR_print_errors_fp(stderr);
    }

    // skをgroupの位数で割った余りを求める(正の数)
    // BN_modでは負の数が返ってくることがあるためBN_nnmodを使用
    BN_nnmod(sk, sk, EC_GROUP_get0_order(group), ctx);

    // メモリ解放
    BN_free(nkck);
    BN_CTX_free(ctx);

    return sk;
}

// ランダムなBIGNUMを生成する関数
BIGNUM* get_randNum(EC_GROUP* group) {
    unsigned char rand_hash[SHA256_DIGEST_LENGTH];
    RAND_bytes(rand_hash, SHA256_DIGEST_LENGTH);

    BIGNUM* randNum = BN_new();
    int degree = EC_GROUP_get_degree(group);
    BN_rand(randNum, degree, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

    return randNum;
}

// リング署名を生成する関数
void SignRing(char message[], int ring_size, EC_POINT* public_keys[],
    EC_GROUP* group, BIGNUM* signer_private_key,
    EC_POINT* signer_public_key, BIGNUM* random_s[], BIGNUM** c_0) {
    // α(=メッセージのハッシュ値)を計算
    BIGNUM* alpha = get_randNum(group);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)message, strlen(message), hash);
    alpha = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);
    // 署名者のsigner_public_keyから署名者が何番目かを特定する
    int signer_k = -1;  // 署名者の番号(k)
    for (int i = 0; i < ring_size; i++) {
        if (EC_POINT_cmp(group, signer_public_key, public_keys[i], NULL) == 0) {
            signer_k = i;
            break;
        }
    }

    // 署名者が見つからなかった場合はエラーを出力して終了
    if (signer_k == -1) {
        fprintf(stderr, "署名者が見つかりませんでした\n");
        return;
    }
    // リング署名を生成していく
    // C_k+1を生成
    EC_POINT* r_point = EC_POINT_new(group);
    EC_POINT_mul(group, r_point, alpha, NULL, NULL, NULL);
    EC_POINT* original_r_point = EC_POINT_dup(r_point, group);

    BIGNUM* C;
    C = H_function(message, r_point, group);
    // printf("C_%02d: %s\n", (signer_k + 1) % ring_size, BN_bn2hex(C));
    if ((signer_k + 1) % ring_size == 0) {
        *c_0 = BN_dup(C);  // C_0を保存
    }

    // C_k+2 ~ C_kを生成
    for (int j = 1; j < ring_size; j++) {
        int i = (signer_k + j) % ring_size;  // i番目のリングメンバー
        random_s[i] = get_randNum(group);
        EC_POINT_mul(group, r_point, random_s[i], public_keys[i], C,
            NULL);  // r_function
        C = H_function(message, r_point, group);
        // printf("C_%02d: %s\n", (i + 1) % ring_size, BN_bn2hex(C));
        if ((i + 1) % ring_size == 0) {
            *c_0 = BN_dup(C);  // C_0を保存
        }
    }

    // C_kとalphaからs_kを計算
    random_s[signer_k] = sk_function(group, alpha, C, signer_private_key);
    // メモリ解放
    EC_POINT_free(r_point);
    BN_free(C);
    BN_free(alpha);

    return;
}

bool VerifyRing(char message[], int ring_size, EC_POINT* public_keys[],
    EC_GROUP* group, BIGNUM* random_s[], BIGNUM* c_0) {
    // リング署名を検証
    EC_POINT* r_point = EC_POINT_new(group);
    BIGNUM* C = BN_dup(c_0);
    //    c_0から始める
    for (int i = 0; i < ring_size; i++) {
        EC_POINT_mul(group, r_point, random_s[i], public_keys[i], C,
            NULL);  // r_function
        C = H_function(message, r_point, group);
        // printf("C_%02d: %s\n", (i + 1) % ring_size, BN_bn2hex(C));
    }

    // C_0とC_kが一致しているかを確認
    if (BN_cmp(c_0, C) != 0) {
        // printf("C_0とCが一致しませんでした\n");
        // printf("C_0: %s\n", BN_bn2hex(c_0));
        // printf("C: %s\n", BN_bn2hex(C));
        return false;
    }

    // メモリ解放
    EC_POINT_free(r_point);
    BN_free(C);

    return true;
}

// String形式からSignRingを呼び出す関数
DLLEXPORT void __stdcall SignRingString(char* message, int ring_size,
    ECDSAPublicKey** publicKeyStrings,
    ECDSAKeyPair* signer_keyPairString, char** random_s_strings,
    char* c_0_string) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM* signer_private_key = BN_new();
    EC_POINT* signer_public_key = EC_POINT_new(group);
    StringToBIGNUM(signer_private_key, signer_keyPairString->privateKey);
    StringToPublicKey(signer_public_key, group, &signer_keyPairString->publicKey);
    EC_POINT** public_keys = (EC_POINT**)malloc(sizeof(EC_POINT*) * ring_size);
    if (public_keys == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < ring_size; i++) {
        public_keys[i] = EC_POINT_new(group);
        StringToPublicKey(public_keys[i], group, publicKeyStrings[i]);
    }
    BIGNUM** random_s = (BIGNUM**)malloc(sizeof(BIGNUM*) * ring_size);
    if (random_s == NULL) {
		fprintf(stderr, "Memory allocation failed\n");
		exit(EXIT_FAILURE);
	}
    BIGNUM* c_0 = BN_new();

    // リング署名を生成
    SignRing(message, ring_size, public_keys, group, signer_private_key,
        signer_public_key, random_s, &c_0);

    // Stringに変換
    for (int i = 0; i < ring_size; i++) {
        BIGNUMToString(random_s[i], random_s_strings[i]);
    }
    BIGNUMToString(c_0, c_0_string);
    // メモリ解放
    for (int i = 0; i < ring_size; i++) {
        EC_POINT_free(public_keys[i]);
        BN_free(random_s[i]);
    }
    EC_GROUP_free(group);
    EC_POINT_free(signer_public_key);
    BN_free(signer_private_key);
    BN_free(c_0);
    free(public_keys);
    free(random_s);

    return;
}

// String形式からVerifyRingを呼び出す関数(リング署名が有効なら1を返す)
DLLEXPORT int __stdcall VerifyRingString(char message[], int ring_size,
    ECDSAPublicKey* publicKeyStrings[],
    char* random_s_strings[], char* c_0_string) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT** public_keys = (EC_POINT**)malloc(sizeof(EC_POINT*) * ring_size);
    if (public_keys == NULL) {
		fprintf(stderr, "Memory allocation failed\n");
		exit(EXIT_FAILURE);
	}

    for (int i = 0; i < ring_size; i++) {
        public_keys[i] = EC_POINT_new(group);
        StringToPublicKey(public_keys[i], group, publicKeyStrings[i]);
    }

    BIGNUM** random_s = (BIGNUM**)malloc(sizeof(BIGNUM*) * ring_size);
    if (random_s == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    BIGNUM* c_0 = BN_new();
    StringToBIGNUM(c_0, c_0_string);
    for (int i = 0; i < ring_size; i++) {
        random_s[i] = BN_new();
        StringToBIGNUM(random_s[i], random_s_strings[i]);
    }

    // リング署名を検証
    bool isValid = false;
    isValid = VerifyRing(message, ring_size, public_keys, group, random_s, c_0);

    // メモリ解放
    for (int i = 0; i < ring_size; i++) {
        EC_POINT_free(public_keys[i]);
        BN_free(random_s[i]);
    }
    EC_GROUP_free(group);
    BN_free(c_0);
    free(public_keys);
    free(random_s);

    return isValid;
}

// 65文字(64文字+null終端)の16進数文字列をランダムに生成する関数
DLLEXPORT int __stdcall GetRandomMessage(char* message) {
    // メッセージをランダムに生成
    unsigned char rand_hash[SHA256_DIGEST_LENGTH];
    RAND_bytes(rand_hash, SHA256_DIGEST_LENGTH);
    BIGNUM* message_bn = BN_new();
    message_bn = BN_bin2bn(rand_hash, SHA256_DIGEST_LENGTH, NULL);
    strcpy_s(message, HEX_UNSIGNED_SIZE, BN_bn2hex(message_bn));
    BN_free(message_bn);
    return 0;
}