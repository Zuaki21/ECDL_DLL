#include "pch.h"
#define DLLEXPORT extern "C" __declspec(dllexport)
#include <stdio.h>
#include <string.h>

typedef struct TestStruct
{
	char a[65];
	char b[65];
	char c[65];
} TestStruct;

DLLEXPORT int __stdcall Test(int a, int b)
{
	return a + b;
}

DLLEXPORT int __stdcall GetString(char* str) {
	strcpy_s(str, sizeof("MARIO"), "MARIO");
	return 0;
}

DLLEXPORT int __stdcall GetStruct(TestStruct* testStruct) {
	strcpy_s(testStruct->a, sizeof("MARIO"), "MARIO");
	strcpy_s(testStruct->b, sizeof("LUIGI"), "LUIGI");
	strcpy_s(testStruct->c, sizeof("PEACH"), "PEACH");
	return 0;
}

DLLEXPORT int __stdcall GetStringArray(int size, char str[][6]) {

	for (int i = 0; i < size; i++) {
		//i番号を5桁の文字列に変換
		sprintf_s(str[i], sizeof("00000"), "%05d", i);
	}
	return 0;
}

void  DoStringPointer(int size, char** str) {
	for (int i = 0; i < size; i++) {
		//i番号を5桁の文字列に変換
		sprintf_s(str[i], sizeof("00000"), "%05d", i);
	}
	return;
}

DLLEXPORT int __stdcall GetStringPointer(int size, char** str) {

	//呼び出した関数から更に別の関数を参照渡しで呼び出した時の挙動を確認するため
	// ここでの変更は実際にUnity側で反映が確認された．
	//DoStringPointer(size, str);
	for (int i = 0; i < size; i++) {
		//i番号を5桁の文字列に変換
		sprintf_s(str[i], sizeof("00000"), "%05d", i);
	}
	return 0;
}

DLLEXPORT int __stdcall GetStructPointer(int size, TestStruct** testStruct) {

	for (int i = 0; i < size; i++) {
		//i番号を5桁の文字列に変換
		sprintf_s(testStruct[i]->a, sizeof("00000"), "%05d", i);
		sprintf_s(testStruct[i]->b, sizeof("00000"), "%05d", i);
		sprintf_s(testStruct[i]->c, sizeof("00000"), "%05d", i);

		testStruct[i]->a[0] = 'A';
		testStruct[i]->b[0] = 'B';
		testStruct[i]->c[0] = 'C';
	}
	return 0;
}