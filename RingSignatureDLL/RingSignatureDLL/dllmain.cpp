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

DLLEXPORT int __stdcall GetStringPointer(int size, char** str) {

	for (int i = 0; i < size; i++) {
		//i番号を5桁の文字列に変換
		sprintf_s(str[i], sizeof("00000"), "%05d", i);
	}
	return 0;
}