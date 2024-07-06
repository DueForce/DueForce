#ifndef __HEADER_NAME_H
#define __HEADER_NAME_H

#include "pin.H"
namespace WINDOWS
{
#include "Windows.h"
}
#include <map>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stack>
#include <set>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>

#define PREMEM_SIZE 0x1000

#define TIMEOUT_SEC 3

using namespace std;

typedef void (*InsertFunc)(RTN rtn);

map<INT32, BOOL> scheme_map;
map<UINT32, BOOL> has_forced;

fstream stap_file("./stap_log.txt", ios::out | ios::app);
FILE* mem_file;

UINT32 global_start, global_end, mmap_base, ret_addr;

WINDOWS::HANDLE hThread;

map<string, InsertFunc> api_map;
map<string, UINT32> str_idx_map;

static char tmp_s[256];
string GetArgValue(const char* rtn_name, ADDRINT arg, int index) {
	string output;

	for (int i = 3; i >= 0; --i) {
		output.push_back("0123456789ABCDEF"[(((uint8_t*)&arg)[i] >> 4) & 0xF]);
		output.push_back("0123456789ABCDEF"[((uint8_t*)&arg)[i] & 0xF]);
	}
	if (str_idx_map[rtn_name] & (1 << index)) {
		stap_file << "(char*)";

		output = "\"";
		output += (char*)arg;
		output += "\"";
	}
	else if (str_idx_map[rtn_name] & (1 << (index + 16))) {
		stap_file << "(wchar_t*)";
		if (arg < 0x10000)return output;
		char* p = (char *) arg;
		output = "";
		while (*p != '\0' || *(p + 1) != '\0') {
			output += *(p);
			p += 2;
		}
		//WideCharToMultiByte(CP_ACP, 0, (wchar_t*) arg, wcslen((wchar_t*)arg) + 1, tmp_s, 256, NULL, NULL);
		//unsigned int converted = 0;
		//wcstombs_s(&converted, tmp_s, 256, (wchar_t*) arg, _TRUNCATE);
		//stap_file << tmp_s;
	}
	return output;
}

VOID TraceCertOpenStore(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceCertOpenSystemStoreA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceCertOpenSystemStoreW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceCertControlStore(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceCertCreateCertificateContext(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceCryptAcquireContextA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceCryptAcquireContextW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceCryptProtectData(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceCryptUnprotectData(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceCryptProtectMemory(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceCryptUnprotectMemory(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceCryptDecrypt(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceCryptEncrypt(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceCryptHashData(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceCryptDecodeMessage(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10, ADDRINT arg11, ADDRINT arg12, ADDRINT arg13)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10) << ","
		<< GetArgValue(rtn_name, arg11, 11) << ","
		<< GetArgValue(rtn_name, arg12, 12) << ","
		<< GetArgValue(rtn_name, arg13, 13)
		<< ")" << endl;
}
VOID TraceCryptDecryptMessage(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceCryptEncryptMessage(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceCryptHashMessage(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9)
		<< ")" << endl;
}
VOID TraceCryptExportKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceCryptGenKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceCryptCreateHash(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceCryptDecodeObjectEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TracePRF(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10)
		<< ")" << endl;
}
VOID TraceSsl3GenerateKeyMaterial(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceEncryptMessage(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceDecryptMessage(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceSetUnhandledExceptionFilter(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceRtlAddVectoredExceptionHandler(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceRtlAddVectoredContinueHandler(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceRtlRemoveVectoredExceptionHandler(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceRtlRemoveVectoredContinueHandler(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceRtlDispatchException(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID Trace_RtlRaiseException(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID Trace_NtRaiseException(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceCreateDirectoryW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceCreateDirectoryExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceRemoveDirectoryA(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceRemoveDirectoryW(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceMoveFileWithProgressW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceFindFirstFileExA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceFindFirstFileExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceCopyFileA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceCopyFileW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceCopyFileExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceDeleteFileW(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetFileType(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetFileSize(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetFileSizeEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetFileInformationByHandle(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetFileInformationByHandleEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceSetFilePointer(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceSetFilePointerEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceSetFileInformationByHandle(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceDeviceIoControl(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceGetSystemDirectoryA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetSystemDirectoryW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetSystemWindowsDirectoryA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetSystemWindowsDirectoryW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetTempPathW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceSetFileAttributesW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetFileAttributesW(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetFileAttributesExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceSetEndOfFile(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetVolumeNameForVolumeMountPointW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceGetVolumePathNamesForVolumeNameW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceGetVolumePathNameW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceGetShortPathNameW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceSearchPathW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceSetFileTime(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceNtCreateFile(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10, ADDRINT arg11)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10) << ","
		<< GetArgValue(rtn_name, arg11, 11)
		<< ")" << endl;
}
VOID TraceNtDeleteFile(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceNtOpenFile(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceNtReadFile(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9)
		<< ")" << endl;
}
VOID TraceNtWriteFile(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9)
		<< ")" << endl;
}
VOID TraceNtDeviceIoControlFile(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10)
		<< ")" << endl;
}
VOID TraceNtQueryDirectoryFile(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10, ADDRINT arg11)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10) << ","
		<< GetArgValue(rtn_name, arg11, 11)
		<< ")" << endl;
}
VOID TraceNtQueryInformationFile(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceNtSetInformationFile(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceNtOpenDirectoryObject(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceNtCreateDirectoryObject(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceNtQueryAttributesFile(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceNtQueryFullAttributesFile(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceCDocument_write(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceCHyperlink_SetUrlComponent(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceCIFrameElement_CreateElement(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceCWindow_AddTimeoutCode(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceCScriptElement_put_src(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceCElement_put_innerHTML(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceCImgElement_put_src(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceCreateJobObjectW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceSetInformationJobObject(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceAssignProcessToJobObject(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetSystemMetrics(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetCursorPos(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetComputerNameA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetComputerNameW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetUserNameA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetUserNameW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetUserNameExA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceGetUserNameExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceEnumWindows(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetDiskFreeSpaceW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceGetDiskFreeSpaceExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceWriteConsoleA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceWriteConsoleW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceSHGetSpecialFolderLocation(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceSHGetFolderPathW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceLookupAccountSidW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceReadCabinetState(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceUuidCreate(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetTimeZoneInformation(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetFileVersionInfoSizeW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetFileVersionInfoSizeExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceGetFileVersionInfoW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceGetFileVersionInfoExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceNotifyBootConfigStatus(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceTaskDialog(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceCreateActCtxW(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceRegisterHotKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceSetStdHandle(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceNetGetJoinInformation(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceNetUserGetInfo(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceNetUserGetLocalGroups(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceNetShareEnum(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceURLDownloadToFileW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceInternetCrackUrlA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceInternetCrackUrlW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceInternetOpenA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceInternetOpenW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceInternetConnectA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceInternetConnectW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceInternetOpenUrlA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceInternetOpenUrlW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceInternetQueryOptionA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceInternetSetOptionA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceHttpOpenRequestA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceHttpOpenRequestW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceHttpSendRequestA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceHttpSendRequestW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceInternetReadFile(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceInternetWriteFile(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceInternetCloseHandle(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceInternetGetConnectedState(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceInternetGetConnectedStateExA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceInternetGetConnectedStateExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceInternetSetStatusCallback(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceDeleteUrlCacheEntryA(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceDeleteUrlCacheEntryW(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceDnsQuery_A(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceDnsQuery_UTF8(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceDnsQuery_W(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID Tracegetaddrinfo(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceGetAddrInfoW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceGetInterfaceInfo(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetAdaptersInfo(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetAdaptersAddresses(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceHttpQueryInfoA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceObtainUserAgentString(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceGetBestInterfaceEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceWNetGetProviderNameW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID Trace_vbe6_StringConcat(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID Tracevbe6_CreateObject(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID Tracevbe6_GetObject(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID Tracevbe6_GetIDFromName(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID Tracevbe6_CallByName(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID Tracevbe6_Invoke(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9)
		<< ")" << endl;
}
VOID Tracevbe6_Shell(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID Tracevbe6_Import(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID Tracevbe6_Open(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID Tracevbe6_Print(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID Tracevbe6_Close(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceCoCreateInstance(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceOleInitialize(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceCoInitializeEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceCoUninitialize(const char* rtn_name)
{
	stap_file << hex << rtn_name << "("
		<< ")" << endl;
}
VOID TraceCoInitializeSecurity(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9)
		<< ")" << endl;
}
VOID TraceCoCreateInstanceEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceCoGetClassObject(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceOleConvertOLESTREAMToIStorage(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceCreateProcessInternalW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10, ADDRINT arg11, ADDRINT arg12)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10) << ","
		<< GetArgValue(rtn_name, arg11, 11) << ","
		<< GetArgValue(rtn_name, arg12, 12)
		<< ")" << endl;
}
VOID TraceShellExecuteExW(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceReadProcessMemory(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceWriteProcessMemory(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID Tracesystem(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceCreateToolhelp32Snapshot(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceProcess32FirstW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceProcess32NextW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceModule32FirstW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceModule32NextW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceNtCreateProcess(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceNtCreateProcessEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9)
		<< ")" << endl;
}
VOID TraceNtCreateUserProcess(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10, ADDRINT arg11)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10) << ","
		<< GetArgValue(rtn_name, arg11, 11)
		<< ")" << endl;
}
VOID TraceRtlCreateUserProcess(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10)
		<< ")" << endl;
}
VOID TraceNtOpenProcess(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceNtTerminateProcess(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceNtCreateSection(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceNtMakeTemporaryObject(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceNtMakePermanentObject(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceNtOpenSection(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceNtUnmapViewOfSection(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceNtAllocateVirtualMemory(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceNtReadVirtualMemory(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceNtWriteVirtualMemory(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceNtProtectVirtualMemory(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceNtFreeVirtualMemory(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceNtMapViewOfSection(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10)
		<< ")" << endl;
}
VOID TraceRegOpenKeyExA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceRegOpenKeyExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceRegCreateKeyExA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9)
		<< ")" << endl;
}
VOID TraceRegCreateKeyExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9)
		<< ")" << endl;
}
VOID TraceRegDeleteKeyA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceRegDeleteKeyW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceRegEnumKeyW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceRegEnumKeyExA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceRegEnumKeyExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceRegEnumValueA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceRegEnumValueW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceRegSetValueExA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceRegSetValueExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceRegQueryValueExA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceRegQueryValueExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceRegDeleteValueA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceRegDeleteValueW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceRegQueryInfoKeyA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10, ADDRINT arg11, ADDRINT arg12)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10) << ","
		<< GetArgValue(rtn_name, arg11, 11) << ","
		<< GetArgValue(rtn_name, arg12, 12)
		<< ")" << endl;
}
VOID TraceRegQueryInfoKeyW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10, ADDRINT arg11, ADDRINT arg12)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10) << ","
		<< GetArgValue(rtn_name, arg11, 11) << ","
		<< GetArgValue(rtn_name, arg12, 12)
		<< ")" << endl;
}
VOID TraceRegCloseKey(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceNtCreateKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceNtOpenKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceNtOpenKeyEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceNtRenameKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceNtReplaceKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceNtEnumerateKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceNtEnumerateValueKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceNtSetValueKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceNtQueryValueKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceNtQueryMultipleValueKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceNtDeleteKey(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceNtDeleteValueKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceNtLoadKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceNtLoadKey2(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceNtLoadKeyEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceNtQueryKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceNtSaveKey(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceNtSaveKeyEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceFindResourceA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceFindResourceW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceFindResourceExA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceFindResourceExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceLoadResource(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceSizeofResource(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceOpenSCManagerA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceOpenSCManagerW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceCreateServiceA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10, ADDRINT arg11, ADDRINT arg12, ADDRINT arg13)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10) << ","
		<< GetArgValue(rtn_name, arg11, 11) << ","
		<< GetArgValue(rtn_name, arg12, 12) << ","
		<< GetArgValue(rtn_name, arg13, 13)
		<< ")" << endl;
}
VOID TraceCreateServiceW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10, ADDRINT arg11, ADDRINT arg12, ADDRINT arg13)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10) << ","
		<< GetArgValue(rtn_name, arg11, 11) << ","
		<< GetArgValue(rtn_name, arg12, 12) << ","
		<< GetArgValue(rtn_name, arg13, 13)
		<< ")" << endl;
}
VOID TraceOpenServiceA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceOpenServiceW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceStartServiceA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceStartServiceW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceControlService(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceDeleteService(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceEnumServicesStatusA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceEnumServicesStatusW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceStartServiceCtrlDispatcherW(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceNtDelayExecution(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceGetLocalTime(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetSystemTime(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetTickCount(const char* rtn_name)
{
	stap_file << hex << rtn_name << "("
		<< ")" << endl;
}
VOID TraceGetSystemTimeAsFileTime(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceNtQuerySystemTime(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TracetimeGetTime(const char* rtn_name)
{
	stap_file << hex << rtn_name << "("
		<< ")" << endl;
}
VOID TraceWSAStartup(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID Tracegethostbyname(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID Tracesocket(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID Tracegetsockname(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID Traceconnect(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID Tracesend(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID Tracesendto(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID Tracerecv(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID Tracerecvfrom(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID Traceaccept(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID Tracebind(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID Tracelisten(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID Traceselect(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID Tracesetsockopt(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID Traceioctlsocket(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID Traceclosesocket(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID Traceshutdown(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceWSAAccept(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceWSARecv(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceWSARecvFrom(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9)
		<< ")" << endl;
}
VOID TraceWSASend(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceWSASendTo(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9)
		<< ")" << endl;
}
VOID TraceWSASocketA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceWSASocketW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceWSAConnect(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceConnectEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceTransmitFile(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceNtCreateMutant(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceNtOpenMutant(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceSetWindowsHookExA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceSetWindowsHookExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceOutputDebugStringA(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceUnhookWindowsHookEx(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceLdrLoadDll(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceLdrUnloadDll(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceLdrGetDllHandle(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceLdrGetProcedureAddress(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceExitWindowsEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceIsDebuggerPresent(const char* rtn_name)
{
	stap_file << hex << rtn_name << "("
		<< ")" << endl;
}
VOID TraceLookupPrivilegeValueW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3)
		<< ")" << endl;
}
VOID TraceNtDuplicateObject(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceNtClose(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetSystemInfo(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetNativeSystemInfo(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceSetErrorMode(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceNtLoadDriver(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceNtUnloadDriver(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetAsyncKeyState(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetKeyboardState(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGetKeyState(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceSendNotifyMessageA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceSendNotifyMessageW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceRtlCompressBuffer(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceRtlDecompressBuffer(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceRtlDecompressFragment(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceGlobalMemoryStatus(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceGlobalMemoryStatusEx(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceNtQuerySystemInformation(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceNtShutdownSystem(const char* rtn_name, ADDRINT arg1)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1)
		<< ")" << endl;
}
VOID TraceCreateThread(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceCreateRemoteThread(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}
VOID TraceCreateRemoteThreadEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceThread32First(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceThread32Next(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceNtCreateThread(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceNtCreateThreadEx(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10, ADDRINT arg11)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10) << ","
		<< GetArgValue(rtn_name, arg11, 11)
		<< ")" << endl;
}
VOID TraceNtOpenThread(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceNtGetContextThread(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceNtSetContextThread(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceNtSuspendThread(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceNtResumeThread(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceNtTerminateThread(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceRtlCreateUserThread(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10)
		<< ")" << endl;
}
VOID TraceNtQueueApcThread(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceFindWindowA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceFindWindowW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2)
		<< ")" << endl;
}
VOID TraceFindWindowExA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceFindWindowExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceGetForegroundWindow(const char* rtn_name)
{
	stap_file << hex << rtn_name << "("
		<< ")" << endl;
}
VOID TraceMessageBoxTimeoutA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceMessageBoxTimeoutW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceDrawTextExA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceDrawTextExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceLoadStringA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID TraceLoadStringW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4)
		<< ")" << endl;
}
VOID Trace_CreateWindowExA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10, ADDRINT arg11, ADDRINT arg12)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10) << ","
		<< GetArgValue(rtn_name, arg11, 11) << ","
		<< GetArgValue(rtn_name, arg12, 12)
		<< ")" << endl;
}
VOID Trace_CreateWindowExW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8, ADDRINT arg9, ADDRINT arg10, ADDRINT arg11, ADDRINT arg12)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8) << ","
		<< GetArgValue(rtn_name, arg9, 9) << ","
		<< GetArgValue(rtn_name, arg10, 10) << ","
		<< GetArgValue(rtn_name, arg11, 11) << ","
		<< GetArgValue(rtn_name, arg12, 12)
		<< ")" << endl;
}
VOID Trace_DialogBoxIndirectParamA(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID Trace_DialogBoxIndirectParamW(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5)
		<< ")" << endl;
}
VOID TraceIWbemServices_ExecQuery(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceIWbemServices_ExecQueryAsync(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6)
		<< ")" << endl;
}
VOID TraceIWbemServices_ExecMethod(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7, ADDRINT arg8)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7) << ","
		<< GetArgValue(rtn_name, arg8, 8)
		<< ")" << endl;
}
VOID TraceIWbemServices_ExecMethodAsync(const char* rtn_name, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7)
{
	stap_file << hex << rtn_name << "("
		<< GetArgValue(rtn_name, arg1, 1) << ","
		<< GetArgValue(rtn_name, arg2, 2) << ","
		<< GetArgValue(rtn_name, arg3, 3) << ","
		<< GetArgValue(rtn_name, arg4, 4) << ","
		<< GetArgValue(rtn_name, arg5, 5) << ","
		<< GetArgValue(rtn_name, arg6, 6) << ","
		<< GetArgValue(rtn_name, arg7, 7)
		<< ")" << endl;
}


VOID InsertCertOpenStore(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCertOpenStore,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertCertOpenSystemStoreA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCertOpenSystemStoreA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertCertOpenSystemStoreW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCertOpenSystemStoreW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertCertControlStore(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCertControlStore,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertCertCreateCertificateContext(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCertCreateCertificateContext,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertCryptAcquireContextA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptAcquireContextA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertCryptAcquireContextW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptAcquireContextW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertCryptProtectData(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptProtectData,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertCryptUnprotectData(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptUnprotectData,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertCryptProtectMemory(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptProtectMemory,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertCryptUnprotectMemory(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptUnprotectMemory,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertCryptDecrypt(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptDecrypt,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertCryptEncrypt(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptEncrypt,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertCryptHashData(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptHashData,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertCryptDecodeMessage(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptDecodeMessage,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 11,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 12,
		IARG_END);
}
VOID InsertCryptDecryptMessage(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptDecryptMessage,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertCryptEncryptMessage(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptEncryptMessage,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertCryptHashMessage(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptHashMessage,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_END);
}
VOID InsertCryptExportKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptExportKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertCryptGenKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptGenKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertCryptCreateHash(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptCreateHash,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertCryptDecodeObjectEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCryptDecodeObjectEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertPRF(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TracePRF,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_END);
}
VOID InsertSsl3GenerateKeyMaterial(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSsl3GenerateKeyMaterial,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertEncryptMessage(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceEncryptMessage,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertDecryptMessage(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceDecryptMessage,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertSetUnhandledExceptionFilter(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSetUnhandledExceptionFilter,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertRtlAddVectoredExceptionHandler(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRtlAddVectoredExceptionHandler,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertRtlAddVectoredContinueHandler(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRtlAddVectoredContinueHandler,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertRtlRemoveVectoredExceptionHandler(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRtlRemoveVectoredExceptionHandler,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertRtlRemoveVectoredContinueHandler(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRtlRemoveVectoredContinueHandler,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertRtlDispatchException(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRtlDispatchException,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID Insert_RtlRaiseException(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Trace_RtlRaiseException,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID Insert_NtRaiseException(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Trace_NtRaiseException,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertCreateDirectoryW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCreateDirectoryW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertCreateDirectoryExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCreateDirectoryExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertRemoveDirectoryA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRemoveDirectoryA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertRemoveDirectoryW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRemoveDirectoryW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertMoveFileWithProgressW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceMoveFileWithProgressW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertFindFirstFileExA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceFindFirstFileExA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertFindFirstFileExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceFindFirstFileExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertCopyFileA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCopyFileA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertCopyFileW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCopyFileW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertCopyFileExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCopyFileExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertDeleteFileW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceDeleteFileW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetFileType(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetFileType,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetFileSize(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetFileSize,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetFileSizeEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetFileSizeEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetFileInformationByHandle(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetFileInformationByHandle,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetFileInformationByHandleEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetFileInformationByHandleEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertSetFilePointer(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSetFilePointer,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertSetFilePointerEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSetFilePointerEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertSetFileInformationByHandle(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSetFileInformationByHandle,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertDeviceIoControl(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceDeviceIoControl,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertGetSystemDirectoryA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetSystemDirectoryA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetSystemDirectoryW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetSystemDirectoryW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetSystemWindowsDirectoryA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetSystemWindowsDirectoryA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetSystemWindowsDirectoryW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetSystemWindowsDirectoryW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetTempPathW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetTempPathW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertSetFileAttributesW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSetFileAttributesW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetFileAttributesW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetFileAttributesW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetFileAttributesExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetFileAttributesExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertSetEndOfFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSetEndOfFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetVolumeNameForVolumeMountPointW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetVolumeNameForVolumeMountPointW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertGetVolumePathNamesForVolumeNameW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetVolumePathNamesForVolumeNameW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertGetVolumePathNameW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetVolumePathNameW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertGetShortPathNameW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetShortPathNameW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertSearchPathW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSearchPathW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertSetFileTime(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSetFileTime,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertNtCreateFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtCreateFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
		IARG_END);
}
VOID InsertNtDeleteFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtDeleteFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertNtOpenFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtOpenFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertNtReadFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtReadFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_END);
}
VOID InsertNtWriteFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtWriteFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_END);
}
VOID InsertNtDeviceIoControlFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtDeviceIoControlFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_END);
}
VOID InsertNtQueryDirectoryFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtQueryDirectoryFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
		IARG_END);
}
VOID InsertNtQueryInformationFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtQueryInformationFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertNtSetInformationFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtSetInformationFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertNtOpenDirectoryObject(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtOpenDirectoryObject,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertNtCreateDirectoryObject(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtCreateDirectoryObject,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertNtQueryAttributesFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtQueryAttributesFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertNtQueryFullAttributesFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtQueryFullAttributesFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertCDocument_write(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCDocument_write,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertCHyperlink_SetUrlComponent(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCHyperlink_SetUrlComponent,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertCIFrameElement_CreateElement(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCIFrameElement_CreateElement,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertCWindow_AddTimeoutCode(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCWindow_AddTimeoutCode,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertCScriptElement_put_src(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCScriptElement_put_src,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertCElement_put_innerHTML(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCElement_put_innerHTML,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertCImgElement_put_src(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCImgElement_put_src,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertCreateJobObjectW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCreateJobObjectW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertSetInformationJobObject(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSetInformationJobObject,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertAssignProcessToJobObject(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceAssignProcessToJobObject,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetSystemMetrics(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetSystemMetrics,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetCursorPos(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetCursorPos,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetComputerNameA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetComputerNameA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetComputerNameW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetComputerNameW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetUserNameA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetUserNameA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetUserNameW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetUserNameW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetUserNameExA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetUserNameExA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertGetUserNameExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetUserNameExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertEnumWindows(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceEnumWindows,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetDiskFreeSpaceW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetDiskFreeSpaceW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertGetDiskFreeSpaceExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetDiskFreeSpaceExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertWriteConsoleA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceWriteConsoleA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertWriteConsoleW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceWriteConsoleW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertSHGetSpecialFolderLocation(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSHGetSpecialFolderLocation,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertSHGetFolderPathW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSHGetFolderPathW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertLookupAccountSidW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceLookupAccountSidW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertReadCabinetState(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceReadCabinetState,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertUuidCreate(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceUuidCreate,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetTimeZoneInformation(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetTimeZoneInformation,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetFileVersionInfoSizeW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetFileVersionInfoSizeW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetFileVersionInfoSizeExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetFileVersionInfoSizeExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertGetFileVersionInfoW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetFileVersionInfoW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertGetFileVersionInfoExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetFileVersionInfoExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertNotifyBootConfigStatus(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNotifyBootConfigStatus,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertTaskDialog(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceTaskDialog,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertCreateActCtxW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCreateActCtxW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertRegisterHotKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegisterHotKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertSetStdHandle(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSetStdHandle,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertNetGetJoinInformation(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNetGetJoinInformation,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertNetUserGetInfo(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNetUserGetInfo,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertNetUserGetLocalGroups(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNetUserGetLocalGroups,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertNetShareEnum(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNetShareEnum,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertURLDownloadToFileW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceURLDownloadToFileW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertInternetCrackUrlA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetCrackUrlA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertInternetCrackUrlW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetCrackUrlW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertInternetOpenA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetOpenA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertInternetOpenW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetOpenW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertInternetConnectA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetConnectA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertInternetConnectW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetConnectW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertInternetOpenUrlA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetOpenUrlA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertInternetOpenUrlW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetOpenUrlW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertInternetQueryOptionA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetQueryOptionA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertInternetSetOptionA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetSetOptionA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertHttpOpenRequestA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceHttpOpenRequestA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertHttpOpenRequestW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceHttpOpenRequestW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertHttpSendRequestA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceHttpSendRequestA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertHttpSendRequestW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceHttpSendRequestW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertInternetReadFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetReadFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertInternetWriteFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetWriteFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertInternetCloseHandle(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetCloseHandle,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertInternetGetConnectedState(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetGetConnectedState,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertInternetGetConnectedStateExA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetGetConnectedStateExA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertInternetGetConnectedStateExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetGetConnectedStateExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertInternetSetStatusCallback(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceInternetSetStatusCallback,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertDeleteUrlCacheEntryA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceDeleteUrlCacheEntryA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertDeleteUrlCacheEntryW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceDeleteUrlCacheEntryW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertDnsQuery_A(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceDnsQuery_A,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertDnsQuery_UTF8(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceDnsQuery_UTF8,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertDnsQuery_W(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceDnsQuery_W,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID Insertgetaddrinfo(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracegetaddrinfo,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertGetAddrInfoW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetAddrInfoW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertGetInterfaceInfo(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetInterfaceInfo,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetAdaptersInfo(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetAdaptersInfo,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetAdaptersAddresses(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetAdaptersAddresses,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertHttpQueryInfoA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceHttpQueryInfoA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertObtainUserAgentString(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceObtainUserAgentString,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertGetBestInterfaceEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetBestInterfaceEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertWNetGetProviderNameW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceWNetGetProviderNameW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID Insert_vbe6_StringConcat(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Trace_vbe6_StringConcat,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID Insertvbe6_CreateObject(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracevbe6_CreateObject,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID Insertvbe6_GetObject(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracevbe6_GetObject,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID Insertvbe6_GetIDFromName(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracevbe6_GetIDFromName,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID Insertvbe6_CallByName(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracevbe6_CallByName,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID Insertvbe6_Invoke(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracevbe6_Invoke,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_END);
}
VOID Insertvbe6_Shell(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracevbe6_Shell,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID Insertvbe6_Import(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracevbe6_Import,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID Insertvbe6_Open(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracevbe6_Open,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID Insertvbe6_Print(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracevbe6_Print,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID Insertvbe6_Close(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracevbe6_Close,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertCoCreateInstance(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCoCreateInstance,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertOleInitialize(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceOleInitialize,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertCoInitializeEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCoInitializeEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertCoUninitialize(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCoUninitialize,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_END);
}
VOID InsertCoInitializeSecurity(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCoInitializeSecurity,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_END);
}
VOID InsertCoCreateInstanceEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCoCreateInstanceEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertCoGetClassObject(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCoGetClassObject,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertOleConvertOLESTREAMToIStorage(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceOleConvertOLESTREAMToIStorage,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertCreateProcessInternalW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCreateProcessInternalW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 11,
		IARG_END);
}
VOID InsertShellExecuteExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceShellExecuteExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertReadProcessMemory(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceReadProcessMemory,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertWriteProcessMemory(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceWriteProcessMemory,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID Insertsystem(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracesystem,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertCreateToolhelp32Snapshot(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCreateToolhelp32Snapshot,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertProcess32FirstW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceProcess32FirstW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertProcess32NextW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceProcess32NextW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertModule32FirstW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceModule32FirstW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertModule32NextW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceModule32NextW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertNtCreateProcess(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtCreateProcess,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertNtCreateProcessEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtCreateProcessEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_END);
}
VOID InsertNtCreateUserProcess(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtCreateUserProcess,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
		IARG_END);
}
VOID InsertRtlCreateUserProcess(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRtlCreateUserProcess,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_END);
}
VOID InsertNtOpenProcess(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtOpenProcess,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertNtTerminateProcess(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtTerminateProcess,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertNtCreateSection(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtCreateSection,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertNtMakeTemporaryObject(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtMakeTemporaryObject,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertNtMakePermanentObject(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtMakePermanentObject,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertNtOpenSection(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtOpenSection,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertNtUnmapViewOfSection(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtUnmapViewOfSection,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertNtAllocateVirtualMemory(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtAllocateVirtualMemory,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertNtReadVirtualMemory(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtReadVirtualMemory,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertNtWriteVirtualMemory(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtWriteVirtualMemory,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertNtProtectVirtualMemory(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtProtectVirtualMemory,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertNtFreeVirtualMemory(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtFreeVirtualMemory,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertNtMapViewOfSection(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtMapViewOfSection,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_END);
}
VOID InsertRegOpenKeyExA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegOpenKeyExA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertRegOpenKeyExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegOpenKeyExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertRegCreateKeyExA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegCreateKeyExA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_END);
}
VOID InsertRegCreateKeyExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegCreateKeyExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_END);
}
VOID InsertRegDeleteKeyA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegDeleteKeyA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertRegDeleteKeyW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegDeleteKeyW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertRegEnumKeyW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegEnumKeyW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertRegEnumKeyExA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegEnumKeyExA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertRegEnumKeyExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegEnumKeyExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertRegEnumValueA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegEnumValueA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertRegEnumValueW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegEnumValueW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertRegSetValueExA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegSetValueExA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertRegSetValueExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegSetValueExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertRegQueryValueExA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegQueryValueExA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertRegQueryValueExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegQueryValueExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertRegDeleteValueA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegDeleteValueA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertRegDeleteValueW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegDeleteValueW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertRegQueryInfoKeyA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegQueryInfoKeyA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 11,
		IARG_END);
}
VOID InsertRegQueryInfoKeyW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegQueryInfoKeyW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 11,
		IARG_END);
}
VOID InsertRegCloseKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRegCloseKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertNtCreateKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtCreateKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertNtOpenKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtOpenKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertNtOpenKeyEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtOpenKeyEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertNtRenameKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtRenameKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertNtReplaceKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtReplaceKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertNtEnumerateKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtEnumerateKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertNtEnumerateValueKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtEnumerateValueKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertNtSetValueKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtSetValueKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertNtQueryValueKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtQueryValueKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertNtQueryMultipleValueKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtQueryMultipleValueKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertNtDeleteKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtDeleteKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertNtDeleteValueKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtDeleteValueKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertNtLoadKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtLoadKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertNtLoadKey2(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtLoadKey2,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertNtLoadKeyEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtLoadKeyEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertNtQueryKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtQueryKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertNtSaveKey(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtSaveKey,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertNtSaveKeyEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtSaveKeyEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertFindResourceA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceFindResourceA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertFindResourceW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceFindResourceW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertFindResourceExA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceFindResourceExA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertFindResourceExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceFindResourceExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertLoadResource(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceLoadResource,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertSizeofResource(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSizeofResource,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertOpenSCManagerA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceOpenSCManagerA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertOpenSCManagerW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceOpenSCManagerW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertCreateServiceA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCreateServiceA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 11,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 12,
		IARG_END);
}
VOID InsertCreateServiceW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCreateServiceW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 11,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 12,
		IARG_END);
}
VOID InsertOpenServiceA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceOpenServiceA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertOpenServiceW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceOpenServiceW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertStartServiceA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceStartServiceA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertStartServiceW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceStartServiceW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertControlService(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceControlService,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertDeleteService(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceDeleteService,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertEnumServicesStatusA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceEnumServicesStatusA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertEnumServicesStatusW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceEnumServicesStatusW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertStartServiceCtrlDispatcherW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceStartServiceCtrlDispatcherW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertNtDelayExecution(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtDelayExecution,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertGetLocalTime(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetLocalTime,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetSystemTime(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetSystemTime,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetTickCount(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetTickCount,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_END);
}
VOID InsertGetSystemTimeAsFileTime(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetSystemTimeAsFileTime,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertNtQuerySystemTime(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtQuerySystemTime,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InserttimeGetTime(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TracetimeGetTime,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_END);
}
VOID InsertWSAStartup(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceWSAStartup,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID Insertgethostbyname(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracegethostbyname,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID Insertsocket(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracesocket,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID Insertgetsockname(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracegetsockname,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID Insertconnect(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Traceconnect,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID Insertsend(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracesend,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID Insertsendto(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracesendto,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID Insertrecv(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracerecv,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID Insertrecvfrom(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracerecvfrom,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID Insertaccept(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Traceaccept,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID Insertbind(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracebind,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID Insertlisten(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracelisten,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID Insertselect(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Traceselect,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID Insertsetsockopt(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Tracesetsockopt,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID Insertioctlsocket(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Traceioctlsocket,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID Insertclosesocket(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Traceclosesocket,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID Insertshutdown(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Traceshutdown,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertWSAAccept(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceWSAAccept,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertWSARecv(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceWSARecv,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertWSARecvFrom(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceWSARecvFrom,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_END);
}
VOID InsertWSASend(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceWSASend,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertWSASendTo(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceWSASendTo,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_END);
}
VOID InsertWSASocketA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceWSASocketA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertWSASocketW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceWSASocketW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertWSAConnect(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceWSAConnect,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertConnectEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceConnectEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertTransmitFile(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceTransmitFile,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertNtCreateMutant(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtCreateMutant,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertNtOpenMutant(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtOpenMutant,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertSetWindowsHookExA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSetWindowsHookExA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertSetWindowsHookExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSetWindowsHookExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertOutputDebugStringA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceOutputDebugStringA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertUnhookWindowsHookEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceUnhookWindowsHookEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertLdrLoadDll(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceLdrLoadDll,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertLdrUnloadDll(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceLdrUnloadDll,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertLdrGetDllHandle(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceLdrGetDllHandle,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertLdrGetProcedureAddress(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceLdrGetProcedureAddress,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertExitWindowsEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceExitWindowsEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertIsDebuggerPresent(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceIsDebuggerPresent,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_END);
}
VOID InsertLookupPrivilegeValueW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceLookupPrivilegeValueW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);
}
VOID InsertNtDuplicateObject(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtDuplicateObject,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertNtClose(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtClose,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetSystemInfo(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetSystemInfo,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetNativeSystemInfo(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetNativeSystemInfo,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertSetErrorMode(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSetErrorMode,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertNtLoadDriver(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtLoadDriver,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertNtUnloadDriver(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtUnloadDriver,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetAsyncKeyState(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetAsyncKeyState,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetKeyboardState(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetKeyboardState,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGetKeyState(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetKeyState,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertSendNotifyMessageA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSendNotifyMessageA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertSendNotifyMessageW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceSendNotifyMessageW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertRtlCompressBuffer(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRtlCompressBuffer,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertRtlDecompressBuffer(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRtlDecompressBuffer,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertRtlDecompressFragment(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRtlDecompressFragment,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertGlobalMemoryStatus(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGlobalMemoryStatus,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertGlobalMemoryStatusEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGlobalMemoryStatusEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertNtQuerySystemInformation(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtQuerySystemInformation,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertNtShutdownSystem(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtShutdownSystem,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_END);
}
VOID InsertCreateThread(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCreateThread,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertCreateRemoteThread(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCreateRemoteThread,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}
VOID InsertCreateRemoteThreadEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceCreateRemoteThreadEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertThread32First(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceThread32First,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertThread32Next(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceThread32Next,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertNtCreateThread(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtCreateThread,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertNtCreateThreadEx(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtCreateThreadEx,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
		IARG_END);
}
VOID InsertNtOpenThread(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtOpenThread,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertNtGetContextThread(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtGetContextThread,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertNtSetContextThread(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtSetContextThread,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertNtSuspendThread(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtSuspendThread,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertNtResumeThread(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtResumeThread,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertNtTerminateThread(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtTerminateThread,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertRtlCreateUserThread(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceRtlCreateUserThread,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_END);
}
VOID InsertNtQueueApcThread(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceNtQueueApcThread,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertFindWindowA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceFindWindowA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertFindWindowW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceFindWindowW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
}
VOID InsertFindWindowExA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceFindWindowExA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertFindWindowExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceFindWindowExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertGetForegroundWindow(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceGetForegroundWindow,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_END);
}
VOID InsertMessageBoxTimeoutA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceMessageBoxTimeoutA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertMessageBoxTimeoutW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceMessageBoxTimeoutW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertDrawTextExA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceDrawTextExA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertDrawTextExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceDrawTextExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertLoadStringA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceLoadStringA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID InsertLoadStringW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceLoadStringW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_END);
}
VOID Insert_CreateWindowExA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Trace_CreateWindowExA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 11,
		IARG_END);
}
VOID Insert_CreateWindowExW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Trace_CreateWindowExW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 11,
		IARG_END);
}
VOID Insert_DialogBoxIndirectParamA(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Trace_DialogBoxIndirectParamA,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID Insert_DialogBoxIndirectParamW(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Trace_DialogBoxIndirectParamW,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_END);
}
VOID InsertIWbemServices_ExecQuery(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceIWbemServices_ExecQuery,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertIWbemServices_ExecQueryAsync(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceIWbemServices_ExecQueryAsync,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_END);
}
VOID InsertIWbemServices_ExecMethod(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceIWbemServices_ExecMethod,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
		IARG_END);
}
VOID InsertIWbemServices_ExecMethodAsync(RTN rtn)
{
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)TraceIWbemServices_ExecMethodAsync,
		IARG_ADDRINT, RTN_Name(rtn).c_str(),
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
		IARG_END);
}

VOID init_map() {
	//hThread = WINDOWS::CreateThread(NULL, 0, SetTimer, NULL, 0, NULL);
	//if (hThread == NULL) {
	//	std::cerr << "[!] FATAL: CreateThread failed" << std::endl;
	//	PIN_ExitProcess(-1);
	//}

	api_map["CertOpenStore"] = &InsertCertOpenStore;
	api_map["CertOpenSystemStoreA"] = &InsertCertOpenSystemStoreA;
	api_map["CertOpenSystemStoreW"] = &InsertCertOpenSystemStoreW;
	api_map["CertControlStore"] = &InsertCertControlStore;
	api_map["CertCreateCertificateContext"] = &InsertCertCreateCertificateContext;
	api_map["CryptAcquireContextA"] = &InsertCryptAcquireContextA;
	api_map["CryptAcquireContextW"] = &InsertCryptAcquireContextW;
	api_map["CryptProtectData"] = &InsertCryptProtectData;
	api_map["CryptUnprotectData"] = &InsertCryptUnprotectData;
	api_map["CryptProtectMemory"] = &InsertCryptProtectMemory;
	api_map["CryptUnprotectMemory"] = &InsertCryptUnprotectMemory;
	api_map["CryptDecrypt"] = &InsertCryptDecrypt;
	api_map["CryptEncrypt"] = &InsertCryptEncrypt;
	api_map["CryptHashData"] = &InsertCryptHashData;
	api_map["CryptDecodeMessage"] = &InsertCryptDecodeMessage;
	api_map["CryptDecryptMessage"] = &InsertCryptDecryptMessage;
	api_map["CryptEncryptMessage"] = &InsertCryptEncryptMessage;
	api_map["CryptHashMessage"] = &InsertCryptHashMessage;
	api_map["CryptExportKey"] = &InsertCryptExportKey;
	api_map["CryptGenKey"] = &InsertCryptGenKey;
	api_map["CryptCreateHash"] = &InsertCryptCreateHash;
	api_map["CryptDecodeObjectEx"] = &InsertCryptDecodeObjectEx;
	api_map["PRF"] = &InsertPRF;
	api_map["Ssl3GenerateKeyMaterial"] = &InsertSsl3GenerateKeyMaterial;
	api_map["EncryptMessage"] = &InsertEncryptMessage;
	api_map["DecryptMessage"] = &InsertDecryptMessage;
	api_map["SetUnhandledExceptionFilter"] = &InsertSetUnhandledExceptionFilter;
	api_map["RtlAddVectoredExceptionHandler"] = &InsertRtlAddVectoredExceptionHandler;
	api_map["RtlAddVectoredContinueHandler"] = &InsertRtlAddVectoredContinueHandler;
	api_map["RtlRemoveVectoredExceptionHandler"] = &InsertRtlRemoveVectoredExceptionHandler;
	api_map["RtlRemoveVectoredContinueHandler"] = &InsertRtlRemoveVectoredContinueHandler;
	api_map["RtlDispatchException"] = &InsertRtlDispatchException;
	api_map["_RtlRaiseException"] = &Insert_RtlRaiseException;
	api_map["_NtRaiseException"] = &Insert_NtRaiseException;
	api_map["CreateDirectoryW"] = &InsertCreateDirectoryW;
	api_map["CreateDirectoryExW"] = &InsertCreateDirectoryExW;
	api_map["RemoveDirectoryA"] = &InsertRemoveDirectoryA;
	api_map["RemoveDirectoryW"] = &InsertRemoveDirectoryW;
	api_map["MoveFileWithProgressW"] = &InsertMoveFileWithProgressW;
	api_map["FindFirstFileExA"] = &InsertFindFirstFileExA;
	api_map["FindFirstFileExW"] = &InsertFindFirstFileExW;
	api_map["CopyFileA"] = &InsertCopyFileA;
	api_map["CopyFileW"] = &InsertCopyFileW;
	api_map["CopyFileExW"] = &InsertCopyFileExW;
	api_map["DeleteFileW"] = &InsertDeleteFileW;
	api_map["GetFileType"] = &InsertGetFileType;
	api_map["GetFileSize"] = &InsertGetFileSize;
	api_map["GetFileSizeEx"] = &InsertGetFileSizeEx;
	api_map["GetFileInformationByHandle"] = &InsertGetFileInformationByHandle;
	api_map["GetFileInformationByHandleEx"] = &InsertGetFileInformationByHandleEx;
	api_map["SetFilePointer"] = &InsertSetFilePointer;
	api_map["SetFilePointerEx"] = &InsertSetFilePointerEx;
	api_map["SetFileInformationByHandle"] = &InsertSetFileInformationByHandle;
	api_map["DeviceIoControl"] = &InsertDeviceIoControl;
	api_map["GetSystemDirectoryA"] = &InsertGetSystemDirectoryA;
	api_map["GetSystemDirectoryW"] = &InsertGetSystemDirectoryW;
	api_map["GetSystemWindowsDirectoryA"] = &InsertGetSystemWindowsDirectoryA;
	api_map["GetSystemWindowsDirectoryW"] = &InsertGetSystemWindowsDirectoryW;
	api_map["GetTempPathW"] = &InsertGetTempPathW;
	api_map["SetFileAttributesW"] = &InsertSetFileAttributesW;
	api_map["GetFileAttributesW"] = &InsertGetFileAttributesW;
	api_map["GetFileAttributesExW"] = &InsertGetFileAttributesExW;
	api_map["SetEndOfFile"] = &InsertSetEndOfFile;
	api_map["GetVolumeNameForVolumeMountPointW"] = &InsertGetVolumeNameForVolumeMountPointW;
	api_map["GetVolumePathNamesForVolumeNameW"] = &InsertGetVolumePathNamesForVolumeNameW;
	api_map["GetVolumePathNameW"] = &InsertGetVolumePathNameW;
	api_map["GetShortPathNameW"] = &InsertGetShortPathNameW;
	api_map["SearchPathW"] = &InsertSearchPathW;
	api_map["SetFileTime"] = &InsertSetFileTime;
	api_map["NtCreateFile"] = &InsertNtCreateFile;
	api_map["NtDeleteFile"] = &InsertNtDeleteFile;
	api_map["NtOpenFile"] = &InsertNtOpenFile;
	api_map["NtReadFile"] = &InsertNtReadFile;
	api_map["NtWriteFile"] = &InsertNtWriteFile;
	api_map["NtDeviceIoControlFile"] = &InsertNtDeviceIoControlFile;
	api_map["NtQueryDirectoryFile"] = &InsertNtQueryDirectoryFile;
	api_map["NtQueryInformationFile"] = &InsertNtQueryInformationFile;
	api_map["NtSetInformationFile"] = &InsertNtSetInformationFile;
	api_map["NtOpenDirectoryObject"] = &InsertNtOpenDirectoryObject;
	api_map["NtCreateDirectoryObject"] = &InsertNtCreateDirectoryObject;
	api_map["NtQueryAttributesFile"] = &InsertNtQueryAttributesFile;
	api_map["NtQueryFullAttributesFile"] = &InsertNtQueryFullAttributesFile;
	api_map["CDocument_write"] = &InsertCDocument_write;
	api_map["CHyperlink_SetUrlComponent"] = &InsertCHyperlink_SetUrlComponent;
	api_map["CIFrameElement_CreateElement"] = &InsertCIFrameElement_CreateElement;
	api_map["CWindow_AddTimeoutCode"] = &InsertCWindow_AddTimeoutCode;
	api_map["CScriptElement_put_src"] = &InsertCScriptElement_put_src;
	api_map["CElement_put_innerHTML"] = &InsertCElement_put_innerHTML;
	api_map["CImgElement_put_src"] = &InsertCImgElement_put_src;
	api_map["CreateJobObjectW"] = &InsertCreateJobObjectW;
	api_map["SetInformationJobObject"] = &InsertSetInformationJobObject;
	api_map["AssignProcessToJobObject"] = &InsertAssignProcessToJobObject;
	api_map["GetSystemMetrics"] = &InsertGetSystemMetrics;
	api_map["GetCursorPos"] = &InsertGetCursorPos;
	api_map["GetComputerNameA"] = &InsertGetComputerNameA;
	api_map["GetComputerNameW"] = &InsertGetComputerNameW;
	api_map["GetUserNameA"] = &InsertGetUserNameA;
	api_map["GetUserNameW"] = &InsertGetUserNameW;
	api_map["GetUserNameExA"] = &InsertGetUserNameExA;
	api_map["GetUserNameExW"] = &InsertGetUserNameExW;
	api_map["EnumWindows"] = &InsertEnumWindows;
	api_map["GetDiskFreeSpaceW"] = &InsertGetDiskFreeSpaceW;
	api_map["GetDiskFreeSpaceExW"] = &InsertGetDiskFreeSpaceExW;
	api_map["WriteConsoleA"] = &InsertWriteConsoleA;
	api_map["WriteConsoleW"] = &InsertWriteConsoleW;
	api_map["SHGetSpecialFolderLocation"] = &InsertSHGetSpecialFolderLocation;
	api_map["SHGetFolderPathW"] = &InsertSHGetFolderPathW;
	api_map["LookupAccountSidW"] = &InsertLookupAccountSidW;
	api_map["ReadCabinetState"] = &InsertReadCabinetState;
	api_map["UuidCreate"] = &InsertUuidCreate;
	api_map["GetTimeZoneInformation"] = &InsertGetTimeZoneInformation;
	api_map["GetFileVersionInfoSizeW"] = &InsertGetFileVersionInfoSizeW;
	api_map["GetFileVersionInfoSizeExW"] = &InsertGetFileVersionInfoSizeExW;
	api_map["GetFileVersionInfoW"] = &InsertGetFileVersionInfoW;
	api_map["GetFileVersionInfoExW"] = &InsertGetFileVersionInfoExW;
	api_map["NotifyBootConfigStatus"] = &InsertNotifyBootConfigStatus;
	api_map["TaskDialog"] = &InsertTaskDialog;
	api_map["CreateActCtxW"] = &InsertCreateActCtxW;
	api_map["RegisterHotKey"] = &InsertRegisterHotKey;
	api_map["SetStdHandle"] = &InsertSetStdHandle;
	api_map["NetGetJoinInformation"] = &InsertNetGetJoinInformation;
	api_map["NetUserGetInfo"] = &InsertNetUserGetInfo;
	api_map["NetUserGetLocalGroups"] = &InsertNetUserGetLocalGroups;
	api_map["NetShareEnum"] = &InsertNetShareEnum;
	api_map["URLDownloadToFileW"] = &InsertURLDownloadToFileW;
	api_map["InternetCrackUrlA"] = &InsertInternetCrackUrlA;
	api_map["InternetCrackUrlW"] = &InsertInternetCrackUrlW;
	api_map["InternetOpenA"] = &InsertInternetOpenA;
	api_map["InternetOpenW"] = &InsertInternetOpenW;
	api_map["InternetConnectA"] = &InsertInternetConnectA;
	api_map["InternetConnectW"] = &InsertInternetConnectW;
	api_map["InternetOpenUrlA"] = &InsertInternetOpenUrlA;
	api_map["InternetOpenUrlW"] = &InsertInternetOpenUrlW;
	api_map["InternetQueryOptionA"] = &InsertInternetQueryOptionA;
	api_map["InternetSetOptionA"] = &InsertInternetSetOptionA;
	api_map["HttpOpenRequestA"] = &InsertHttpOpenRequestA;
	api_map["HttpOpenRequestW"] = &InsertHttpOpenRequestW;
	api_map["HttpSendRequestA"] = &InsertHttpSendRequestA;
	api_map["HttpSendRequestW"] = &InsertHttpSendRequestW;
	api_map["InternetReadFile"] = &InsertInternetReadFile;
	api_map["InternetWriteFile"] = &InsertInternetWriteFile;
	api_map["InternetCloseHandle"] = &InsertInternetCloseHandle;
	api_map["InternetGetConnectedState"] = &InsertInternetGetConnectedState;
	api_map["InternetGetConnectedStateExA"] = &InsertInternetGetConnectedStateExA;
	api_map["InternetGetConnectedStateExW"] = &InsertInternetGetConnectedStateExW;
	api_map["InternetSetStatusCallback"] = &InsertInternetSetStatusCallback;
	api_map["DeleteUrlCacheEntryA"] = &InsertDeleteUrlCacheEntryA;
	api_map["DeleteUrlCacheEntryW"] = &InsertDeleteUrlCacheEntryW;
	api_map["DnsQuery_A"] = &InsertDnsQuery_A;
	api_map["DnsQuery_UTF8"] = &InsertDnsQuery_UTF8;
	api_map["DnsQuery_W"] = &InsertDnsQuery_W;
	api_map["getaddrinfo"] = &Insertgetaddrinfo;
	api_map["GetAddrInfoW"] = &InsertGetAddrInfoW;
	api_map["GetInterfaceInfo"] = &InsertGetInterfaceInfo;
	api_map["GetAdaptersInfo"] = &InsertGetAdaptersInfo;
	api_map["GetAdaptersAddresses"] = &InsertGetAdaptersAddresses;
	api_map["HttpQueryInfoA"] = &InsertHttpQueryInfoA;
	api_map["ObtainUserAgentString"] = &InsertObtainUserAgentString;
	api_map["GetBestInterfaceEx"] = &InsertGetBestInterfaceEx;
	api_map["WNetGetProviderNameW"] = &InsertWNetGetProviderNameW;
	api_map["_vbe6_StringConcat"] = &Insert_vbe6_StringConcat;
	api_map["vbe6_CreateObject"] = &Insertvbe6_CreateObject;
	api_map["vbe6_GetObject"] = &Insertvbe6_GetObject;
	api_map["vbe6_GetIDFromName"] = &Insertvbe6_GetIDFromName;
	api_map["vbe6_CallByName"] = &Insertvbe6_CallByName;
	api_map["vbe6_Invoke"] = &Insertvbe6_Invoke;
	api_map["vbe6_Shell"] = &Insertvbe6_Shell;
	api_map["vbe6_Import"] = &Insertvbe6_Import;
	api_map["vbe6_Open"] = &Insertvbe6_Open;
	api_map["vbe6_Print"] = &Insertvbe6_Print;
	api_map["vbe6_Close"] = &Insertvbe6_Close;
	api_map["CoCreateInstance"] = &InsertCoCreateInstance;
	api_map["OleInitialize"] = &InsertOleInitialize;
	api_map["CoInitializeEx"] = &InsertCoInitializeEx;
	api_map["CoUninitialize"] = &InsertCoUninitialize;
	api_map["CoInitializeSecurity"] = &InsertCoInitializeSecurity;
	api_map["CoCreateInstanceEx"] = &InsertCoCreateInstanceEx;
	api_map["CoGetClassObject"] = &InsertCoGetClassObject;
	api_map["OleConvertOLESTREAMToIStorage"] = &InsertOleConvertOLESTREAMToIStorage;
	api_map["CreateProcessInternalW"] = &InsertCreateProcessInternalW;
	api_map["ShellExecuteExW"] = &InsertShellExecuteExW;
	api_map["ReadProcessMemory"] = &InsertReadProcessMemory;
	api_map["WriteProcessMemory"] = &InsertWriteProcessMemory;
	api_map["system"] = &Insertsystem;
	api_map["CreateToolhelp32Snapshot"] = &InsertCreateToolhelp32Snapshot;
	api_map["Process32FirstW"] = &InsertProcess32FirstW;
	api_map["Process32NextW"] = &InsertProcess32NextW;
	api_map["Module32FirstW"] = &InsertModule32FirstW;
	api_map["Module32NextW"] = &InsertModule32NextW;
	api_map["NtCreateProcess"] = &InsertNtCreateProcess;
	api_map["NtCreateProcessEx"] = &InsertNtCreateProcessEx;
	api_map["NtCreateUserProcess"] = &InsertNtCreateUserProcess;
	api_map["RtlCreateUserProcess"] = &InsertRtlCreateUserProcess;
	api_map["NtOpenProcess"] = &InsertNtOpenProcess;
	api_map["NtTerminateProcess"] = &InsertNtTerminateProcess;
	api_map["NtCreateSection"] = &InsertNtCreateSection;
	api_map["NtMakeTemporaryObject"] = &InsertNtMakeTemporaryObject;
	api_map["NtMakePermanentObject"] = &InsertNtMakePermanentObject;
	api_map["NtOpenSection"] = &InsertNtOpenSection;
	api_map["NtUnmapViewOfSection"] = &InsertNtUnmapViewOfSection;
	api_map["NtAllocateVirtualMemory"] = &InsertNtAllocateVirtualMemory;
	api_map["NtReadVirtualMemory"] = &InsertNtReadVirtualMemory;
	api_map["NtWriteVirtualMemory"] = &InsertNtWriteVirtualMemory;
	api_map["NtProtectVirtualMemory"] = &InsertNtProtectVirtualMemory;
	api_map["NtFreeVirtualMemory"] = &InsertNtFreeVirtualMemory;
	api_map["NtMapViewOfSection"] = &InsertNtMapViewOfSection;
	api_map["RegOpenKeyExA"] = &InsertRegOpenKeyExA;
	api_map["RegOpenKeyExW"] = &InsertRegOpenKeyExW;
	api_map["RegCreateKeyExA"] = &InsertRegCreateKeyExA;
	api_map["RegCreateKeyExW"] = &InsertRegCreateKeyExW;
	api_map["RegDeleteKeyA"] = &InsertRegDeleteKeyA;
	api_map["RegDeleteKeyW"] = &InsertRegDeleteKeyW;
	api_map["RegEnumKeyW"] = &InsertRegEnumKeyW;
	api_map["RegEnumKeyExA"] = &InsertRegEnumKeyExA;
	api_map["RegEnumKeyExW"] = &InsertRegEnumKeyExW;
	api_map["RegEnumValueA"] = &InsertRegEnumValueA;
	api_map["RegEnumValueW"] = &InsertRegEnumValueW;
	api_map["RegSetValueExA"] = &InsertRegSetValueExA;
	api_map["RegSetValueExW"] = &InsertRegSetValueExW;
	api_map["RegQueryValueExA"] = &InsertRegQueryValueExA;
	api_map["RegQueryValueExW"] = &InsertRegQueryValueExW;
	api_map["RegDeleteValueA"] = &InsertRegDeleteValueA;
	api_map["RegDeleteValueW"] = &InsertRegDeleteValueW;
	api_map["RegQueryInfoKeyA"] = &InsertRegQueryInfoKeyA;
	api_map["RegQueryInfoKeyW"] = &InsertRegQueryInfoKeyW;
	api_map["RegCloseKey"] = &InsertRegCloseKey;
	api_map["NtCreateKey"] = &InsertNtCreateKey;
	api_map["NtOpenKey"] = &InsertNtOpenKey;
	api_map["NtOpenKeyEx"] = &InsertNtOpenKeyEx;
	api_map["NtRenameKey"] = &InsertNtRenameKey;
	api_map["NtReplaceKey"] = &InsertNtReplaceKey;
	api_map["NtEnumerateKey"] = &InsertNtEnumerateKey;
	api_map["NtEnumerateValueKey"] = &InsertNtEnumerateValueKey;
	api_map["NtSetValueKey"] = &InsertNtSetValueKey;
	api_map["NtQueryValueKey"] = &InsertNtQueryValueKey;
	api_map["NtQueryMultipleValueKey"] = &InsertNtQueryMultipleValueKey;
	api_map["NtDeleteKey"] = &InsertNtDeleteKey;
	api_map["NtDeleteValueKey"] = &InsertNtDeleteValueKey;
	api_map["NtLoadKey"] = &InsertNtLoadKey;
	api_map["NtLoadKey2"] = &InsertNtLoadKey2;
	api_map["NtLoadKeyEx"] = &InsertNtLoadKeyEx;
	api_map["NtQueryKey"] = &InsertNtQueryKey;
	api_map["NtSaveKey"] = &InsertNtSaveKey;
	api_map["NtSaveKeyEx"] = &InsertNtSaveKeyEx;
	api_map["FindResourceA"] = &InsertFindResourceA;
	api_map["FindResourceW"] = &InsertFindResourceW;
	api_map["FindResourceExA"] = &InsertFindResourceExA;
	api_map["FindResourceExW"] = &InsertFindResourceExW;
	api_map["LoadResource"] = &InsertLoadResource;
	api_map["SizeofResource"] = &InsertSizeofResource;
	api_map["OpenSCManagerA"] = &InsertOpenSCManagerA;
	api_map["OpenSCManagerW"] = &InsertOpenSCManagerW;
	api_map["CreateServiceA"] = &InsertCreateServiceA;
	api_map["CreateServiceW"] = &InsertCreateServiceW;
	api_map["OpenServiceA"] = &InsertOpenServiceA;
	api_map["OpenServiceW"] = &InsertOpenServiceW;
	api_map["StartServiceA"] = &InsertStartServiceA;
	api_map["StartServiceW"] = &InsertStartServiceW;
	api_map["ControlService"] = &InsertControlService;
	api_map["DeleteService"] = &InsertDeleteService;
	api_map["EnumServicesStatusA"] = &InsertEnumServicesStatusA;
	api_map["EnumServicesStatusW"] = &InsertEnumServicesStatusW;
	api_map["StartServiceCtrlDispatcherW"] = &InsertStartServiceCtrlDispatcherW;
	api_map["NtDelayExecution"] = &InsertNtDelayExecution;
	api_map["GetLocalTime"] = &InsertGetLocalTime;
	api_map["GetSystemTime"] = &InsertGetSystemTime;
	api_map["GetTickCount"] = &InsertGetTickCount;
	api_map["GetSystemTimeAsFileTime"] = &InsertGetSystemTimeAsFileTime;
	api_map["NtQuerySystemTime"] = &InsertNtQuerySystemTime;
	api_map["timeGetTime"] = &InserttimeGetTime;
	api_map["WSAStartup"] = &InsertWSAStartup;
	api_map["gethostbyname"] = &Insertgethostbyname;
	api_map["socket"] = &Insertsocket;
	api_map["getsockname"] = &Insertgetsockname;
	api_map["connect"] = &Insertconnect;
	api_map["send"] = &Insertsend;
	api_map["sendto"] = &Insertsendto;
	api_map["recv"] = &Insertrecv;
	api_map["recvfrom"] = &Insertrecvfrom;
	api_map["accept"] = &Insertaccept;
	api_map["bind"] = &Insertbind;
	api_map["listen"] = &Insertlisten;
	api_map["select"] = &Insertselect;
	api_map["setsockopt"] = &Insertsetsockopt;
	api_map["ioctlsocket"] = &Insertioctlsocket;
	api_map["closesocket"] = &Insertclosesocket;
	api_map["shutdown"] = &Insertshutdown;
	api_map["WSAAccept"] = &InsertWSAAccept;
	api_map["WSARecv"] = &InsertWSARecv;
	api_map["WSARecvFrom"] = &InsertWSARecvFrom;
	api_map["WSASend"] = &InsertWSASend;
	api_map["WSASendTo"] = &InsertWSASendTo;
	api_map["WSASocketA"] = &InsertWSASocketA;
	api_map["WSASocketW"] = &InsertWSASocketW;
	api_map["WSAConnect"] = &InsertWSAConnect;
	api_map["ConnectEx"] = &InsertConnectEx;
	api_map["TransmitFile"] = &InsertTransmitFile;
	api_map["NtCreateMutant"] = &InsertNtCreateMutant;
	api_map["NtOpenMutant"] = &InsertNtOpenMutant;
	api_map["SetWindowsHookExA"] = &InsertSetWindowsHookExA;
	api_map["SetWindowsHookExW"] = &InsertSetWindowsHookExW;
	api_map["OutputDebugStringA"] = &InsertOutputDebugStringA;
	api_map["UnhookWindowsHookEx"] = &InsertUnhookWindowsHookEx;
	api_map["LdrLoadDll"] = &InsertLdrLoadDll;
	api_map["LdrUnloadDll"] = &InsertLdrUnloadDll;
	api_map["LdrGetDllHandle"] = &InsertLdrGetDllHandle;
	api_map["LdrGetProcedureAddress"] = &InsertLdrGetProcedureAddress;
	api_map["ExitWindowsEx"] = &InsertExitWindowsEx;
	api_map["IsDebuggerPresent"] = &InsertIsDebuggerPresent;
	api_map["LookupPrivilegeValueW"] = &InsertLookupPrivilegeValueW;
	api_map["NtDuplicateObject"] = &InsertNtDuplicateObject;
	api_map["NtClose"] = &InsertNtClose;
	api_map["GetSystemInfo"] = &InsertGetSystemInfo;
	api_map["GetNativeSystemInfo"] = &InsertGetNativeSystemInfo;
	api_map["SetErrorMode"] = &InsertSetErrorMode;
	api_map["NtLoadDriver"] = &InsertNtLoadDriver;
	api_map["NtUnloadDriver"] = &InsertNtUnloadDriver;
	api_map["GetAsyncKeyState"] = &InsertGetAsyncKeyState;
	api_map["GetKeyboardState"] = &InsertGetKeyboardState;
	api_map["GetKeyState"] = &InsertGetKeyState;
	api_map["SendNotifyMessageA"] = &InsertSendNotifyMessageA;
	api_map["SendNotifyMessageW"] = &InsertSendNotifyMessageW;
	api_map["RtlCompressBuffer"] = &InsertRtlCompressBuffer;
	api_map["RtlDecompressBuffer"] = &InsertRtlDecompressBuffer;
	api_map["RtlDecompressFragment"] = &InsertRtlDecompressFragment;
	api_map["GlobalMemoryStatus"] = &InsertGlobalMemoryStatus;
	api_map["GlobalMemoryStatusEx"] = &InsertGlobalMemoryStatusEx;
	api_map["NtQuerySystemInformation"] = &InsertNtQuerySystemInformation;
	api_map["NtShutdownSystem"] = &InsertNtShutdownSystem;
	api_map["CreateThread"] = &InsertCreateThread;
	api_map["CreateRemoteThread"] = &InsertCreateRemoteThread;
	api_map["CreateRemoteThreadEx"] = &InsertCreateRemoteThreadEx;
	api_map["Thread32First"] = &InsertThread32First;
	api_map["Thread32Next"] = &InsertThread32Next;
	api_map["NtCreateThread"] = &InsertNtCreateThread;
	api_map["NtCreateThreadEx"] = &InsertNtCreateThreadEx;
	api_map["NtOpenThread"] = &InsertNtOpenThread;
	api_map["NtGetContextThread"] = &InsertNtGetContextThread;
	api_map["NtSetContextThread"] = &InsertNtSetContextThread;
	api_map["NtSuspendThread"] = &InsertNtSuspendThread;
	api_map["NtResumeThread"] = &InsertNtResumeThread;
	api_map["NtTerminateThread"] = &InsertNtTerminateThread;
	api_map["RtlCreateUserThread"] = &InsertRtlCreateUserThread;
	api_map["NtQueueApcThread"] = &InsertNtQueueApcThread;
	api_map["FindWindowA"] = &InsertFindWindowA;
	api_map["FindWindowW"] = &InsertFindWindowW;
	api_map["FindWindowExA"] = &InsertFindWindowExA;
	api_map["FindWindowExW"] = &InsertFindWindowExW;
	api_map["GetForegroundWindow"] = &InsertGetForegroundWindow;
	api_map["MessageBoxTimeoutA"] = &InsertMessageBoxTimeoutA;
	api_map["MessageBoxTimeoutW"] = &InsertMessageBoxTimeoutW;
	api_map["DrawTextExA"] = &InsertDrawTextExA;
	api_map["DrawTextExW"] = &InsertDrawTextExW;
	api_map["LoadStringA"] = &InsertLoadStringA;
	api_map["LoadStringW"] = &InsertLoadStringW;
	api_map["_CreateWindowExA"] = &Insert_CreateWindowExA;
	api_map["_CreateWindowExW"] = &Insert_CreateWindowExW;
	api_map["_DialogBoxIndirectParamA"] = &Insert_DialogBoxIndirectParamA;
	api_map["_DialogBoxIndirectParamW"] = &Insert_DialogBoxIndirectParamW;
	api_map["IWbemServices_ExecQuery"] = &InsertIWbemServices_ExecQuery;
	api_map["IWbemServices_ExecQueryAsync"] = &InsertIWbemServices_ExecQueryAsync;
	api_map["IWbemServices_ExecMethod"] = &InsertIWbemServices_ExecMethod;
	api_map["IWbemServices_ExecMethodAsync"] = &InsertIWbemServices_ExecMethodAsync;

	str_idx_map.insert({ "NtDelayExecution", 0 });
	str_idx_map.insert({ "GetLocalTime", 0 });
	str_idx_map.insert({ "GetSystemTime", 0 });
	str_idx_map.insert({ "GetTickCount", 0 });
	str_idx_map.insert({ "NtQuerySystemTime", 0 });
	str_idx_map.insert({ "timeGetTime", 0 });
	str_idx_map.insert({ "NtCreateProcess", 0 });
	str_idx_map.insert({ "NtCreateProcessEx", 0 });
	str_idx_map.insert({ "NtCreateUserProcess", 0 });
	str_idx_map.insert({ "RtlCreateUserProcess", 0 });
	str_idx_map.insert({ "NtOpenProcess", 0 });
	str_idx_map.insert({ "NtTerminateProcess", 0 });
	str_idx_map.insert({ "NtCreateSection", 0 });
	str_idx_map.insert({ "NtMakeTemporaryObject", 0 });
	str_idx_map.insert({ "NtMakePermanentObject", 0 });
	str_idx_map.insert({ "NtOpenSection", 0 });
	str_idx_map.insert({ "NtUnmapViewOfSection", 0 });
	str_idx_map.insert({ "NtAllocateVirtualMemory", 0 });
	str_idx_map.insert({ "NtReadVirtualMemory", 0 });
	str_idx_map.insert({ "NtWriteVirtualMemory", 0 });
	str_idx_map.insert({ "NtProtectVirtualMemory", 0 });
	str_idx_map.insert({ "NtFreeVirtualMemory", 0 });
	str_idx_map.insert({ "NtMapViewOfSection", 0 });
	str_idx_map.insert({ "CertOpenStore", 2 });
	str_idx_map.insert({ "CertOpenSystemStoreA", 4 });
	str_idx_map.insert({ "CertOpenSystemStoreW", 262144 });
	str_idx_map.insert({ "CertControlStore", 0 });
	str_idx_map.insert({ "CertCreateCertificateContext", 0 });
	str_idx_map.insert({ "CryptAcquireContextA", 12 });
	str_idx_map.insert({ "CryptAcquireContextW", 786432 });
	str_idx_map.insert({ "CryptProtectData", 262144 });
	str_idx_map.insert({ "CryptUnprotectData", 262144 });
	str_idx_map.insert({ "CryptProtectMemory", 0 });
	str_idx_map.insert({ "CryptUnprotectMemory", 0 });
	str_idx_map.insert({ "CryptDecrypt", 0 });
	str_idx_map.insert({ "CryptEncrypt", 0 });
	str_idx_map.insert({ "CryptHashData", 0 });
	str_idx_map.insert({ "CryptDecodeMessage", 0 });
	str_idx_map.insert({ "CryptDecryptMessage", 0 });
	str_idx_map.insert({ "CryptEncryptMessage", 0 });
	str_idx_map.insert({ "CryptHashMessage", 0 });
	str_idx_map.insert({ "CryptExportKey", 0 });
	str_idx_map.insert({ "CryptGenKey", 0 });
	str_idx_map.insert({ "CryptCreateHash", 0 });
	str_idx_map.insert({ "CryptDecodeObjectEx", 4 });
	str_idx_map.insert({ "PRF", 0 });
	str_idx_map.insert({ "Ssl3GenerateKeyMaterial", 0 });
	str_idx_map.insert({ "EncryptMessage", 0 });
	str_idx_map.insert({ "DecryptMessage", 0 });
	str_idx_map.insert({ "CoCreateInstance", 0 });
	str_idx_map.insert({ "OleInitialize", 0 });
	str_idx_map.insert({ "CoInitializeEx", 0 });
	str_idx_map.insert({ "CoUninitialize", 0 });
	str_idx_map.insert({ "CoCreateInstanceEx", 0 });
	str_idx_map.insert({ "CoGetClassObject", 0 });
	str_idx_map.insert({ "OleConvertOLESTREAMToIStorage", 0 });
	str_idx_map.insert({ "SetWindowsHookExA", 0 });
	str_idx_map.insert({ "SetWindowsHookExW", 0 });
	str_idx_map.insert({ "OutputDebugStringA", 2 });
	str_idx_map.insert({ "UnhookWindowsHookEx", 0 });
	str_idx_map.insert({ "LdrLoadDll", 131072 });
	str_idx_map.insert({ "LdrUnloadDll", 0 });
	str_idx_map.insert({ "LdrGetDllHandle", 0 });
	str_idx_map.insert({ "LdrGetProcedureAddress", 4 });
	str_idx_map.insert({ "ExitWindowsEx", 0 });
	str_idx_map.insert({ "IsDebuggerPresent", 393216 });
	str_idx_map.insert({ "NtDuplicateObject", 0 });
	str_idx_map.insert({ "NtClose", 0 });
	str_idx_map.insert({ "GetSystemInfo", 0 });
	str_idx_map.insert({ "GetNativeSystemInfo", 0 });
	str_idx_map.insert({ "SetErrorMode", 0 });
	str_idx_map.insert({ "NtLoadDriver", 0 });
	str_idx_map.insert({ "NtUnloadDriver", 0 });
	str_idx_map.insert({ "GetAsyncKeyState", 0 });
	str_idx_map.insert({ "GetKeyboardState", 0 });
	str_idx_map.insert({ "GetKeyState", 0 });
	str_idx_map.insert({ "SendNotifyMessageA", 0 });
	str_idx_map.insert({ "SendNotifyMessageW", 0 });
	str_idx_map.insert({ "RtlCompressBuffer", 0 });
	str_idx_map.insert({ "RtlDecompressBuffer", 0 });
	str_idx_map.insert({ "RtlDecompressFragment", 0 });
	str_idx_map.insert({ "GlobalMemoryStatus", 0 });
	str_idx_map.insert({ "GlobalMemoryStatusEx", 0 });
	str_idx_map.insert({ "NtQuerySystemInformation", 0 });
	str_idx_map.insert({ "NtShutdownSystem", 0 });
	str_idx_map.insert({ "OpenSCManagerA", 6 });
	str_idx_map.insert({ "OpenSCManagerW", 393216 });
	str_idx_map.insert({ "CreateServiceA", 15116 });
	str_idx_map.insert({ "CreateServiceW", 990642176 });
	str_idx_map.insert({ "OpenServiceA", 4 });
	str_idx_map.insert({ "OpenServiceW", 262144 });
	str_idx_map.insert({ "StartServiceA", 8 });
	str_idx_map.insert({ "StartServiceW", 524288 });
	str_idx_map.insert({ "ControlService", 0 });
	str_idx_map.insert({ "DeleteService", 0 });
	str_idx_map.insert({ "EnumServicesStatusA", 0 });
	str_idx_map.insert({ "EnumServicesStatusW", 0 });
	str_idx_map.insert({ "StartServiceCtrlDispatcherW", 0 });
	str_idx_map.insert({ "CreateDirectoryW", 131072 });
	str_idx_map.insert({ "CreateDirectoryExW", 393216 });
	str_idx_map.insert({ "RemoveDirectoryA", 2 });
	str_idx_map.insert({ "RemoveDirectoryW", 131072 });
	str_idx_map.insert({ "MoveFileWithProgressW", 393216 });
	str_idx_map.insert({ "FindFirstFileExA", 2 });
	str_idx_map.insert({ "FindFirstFileExW", 131072 });
	str_idx_map.insert({ "CopyFileA", 6 });
	str_idx_map.insert({ "CopyFileW", 393216 });
	str_idx_map.insert({ "CopyFileExW", 393216 });
	str_idx_map.insert({ "DeleteFileW", 131072 });
	str_idx_map.insert({ "GetFileType", 0 });
	str_idx_map.insert({ "GetFileSize", 0 });
	str_idx_map.insert({ "GetFileSizeEx", 0 });
	str_idx_map.insert({ "GetFileInformationByHandle", 0 });
	str_idx_map.insert({ "GetFileInformationByHandleEx", 0 });
	str_idx_map.insert({ "SetFilePointer", 0 });
	str_idx_map.insert({ "SetFilePointerEx", 0 });
	str_idx_map.insert({ "SetFileInformationByHandle", 0 });
	str_idx_map.insert({ "DeviceIoControl", 0 });
	str_idx_map.insert({ "GetSystemDirectoryA", 2 });
	str_idx_map.insert({ "GetSystemDirectoryW", 131072 });
	str_idx_map.insert({ "GetSystemWindowsDirectoryA", 2 });
	str_idx_map.insert({ "GetSystemWindowsDirectoryW", 131072 });
	str_idx_map.insert({ "GetTempPathW", 262144 });
	str_idx_map.insert({ "SetFileAttributesW", 131072 });
	str_idx_map.insert({ "GetFileAttributesW", 131072 });
	str_idx_map.insert({ "GetFileAttributesExW", 131072 });
	str_idx_map.insert({ "SetEndOfFile", 0 });
	str_idx_map.insert({ "GetVolumeNameForVolumeMountPointW", 393216 });
	str_idx_map.insert({ "GetVolumePathNamesForVolumeNameW", 393216 });
	str_idx_map.insert({ "GetVolumePathNameW", 393216 });
	str_idx_map.insert({ "GetShortPathNameW", 393216 });
	str_idx_map.insert({ "SearchPathW", 7208960 });
	str_idx_map.insert({ "SetFileTime", 0 });
	str_idx_map.insert({ "RegOpenKeyExA", 4 });
	str_idx_map.insert({ "RegOpenKeyExW", 262144 });
	str_idx_map.insert({ "RegCreateKeyExA", 20 });
	str_idx_map.insert({ "RegCreateKeyExW", 1310720 });
	str_idx_map.insert({ "RegDeleteKeyA", 4 });
	str_idx_map.insert({ "RegDeleteKeyW", 262144 });
	str_idx_map.insert({ "RegEnumKeyW", 524288 });
	str_idx_map.insert({ "RegEnumKeyExA", 72 });
	str_idx_map.insert({ "RegEnumKeyExW", 4718592 });
	str_idx_map.insert({ "RegEnumValueA", 8 });
	str_idx_map.insert({ "RegEnumValueW", 524288 });
	str_idx_map.insert({ "RegSetValueExA", 4 });
	str_idx_map.insert({ "RegSetValueExW", 262144 });
	str_idx_map.insert({ "RegQueryValueExA", 4 });
	str_idx_map.insert({ "RegQueryValueExW", 262144 });
	str_idx_map.insert({ "RegDeleteValueA", 4 });
	str_idx_map.insert({ "RegDeleteValueW", 262144 });
	str_idx_map.insert({ "RegQueryInfoKeyA", 4 });
	str_idx_map.insert({ "RegQueryInfoKeyW", 262144 });
	str_idx_map.insert({ "RegCloseKey", 0 });
	str_idx_map.insert({ "NtCreateFile", 0 });
	str_idx_map.insert({ "NtDeleteFile", 0 });
	str_idx_map.insert({ "NtOpenFile", 0 });
	str_idx_map.insert({ "NtReadFile", 0 });
	str_idx_map.insert({ "NtWriteFile", 0 });
	str_idx_map.insert({ "NtDeviceIoControlFile", 0 });
	str_idx_map.insert({ "NtQueryDirectoryFile", 0 });
	str_idx_map.insert({ "NtQueryInformationFile", 0 });
	str_idx_map.insert({ "NtSetInformationFile", 0 });
	str_idx_map.insert({ "NtOpenDirectoryObject", 0 });
	str_idx_map.insert({ "NtCreateDirectoryObject", 0 });
	str_idx_map.insert({ "NtQueryAttributesFile", 0 });
	str_idx_map.insert({ "NtQueryFullAttributesFile", 0 });
	str_idx_map.insert({ "CDocument_write", 0 });
	str_idx_map.insert({ "CHyperlink_SetUrlComponent", 0 });
	str_idx_map.insert({ "CIFrameElement_CreateElement", 0 });
	str_idx_map.insert({ "CWindow_AddTimeoutCode", 0 });
	str_idx_map.insert({ "CScriptElement_put_src", 0 });
	str_idx_map.insert({ "CElement_put_innerHTML", 0 });
	str_idx_map.insert({ "CImgElement_put_src", 0 });
	str_idx_map.insert({ "NtCreateMutant", 0 });
	str_idx_map.insert({ "NtOpenMutant", 0 });
	str_idx_map.insert({ "NetShareEnum", 131072 });
	str_idx_map.insert({ "NtCreateThread", 0 });
	str_idx_map.insert({ "NtCreateThreadEx", 0 });
	str_idx_map.insert({ "NtOpenThread", 0 });
	str_idx_map.insert({ "NtGetContextThread", 0 });
	str_idx_map.insert({ "NtSetContextThread", 0 });
	str_idx_map.insert({ "NtSuspendThread", 0 });
	str_idx_map.insert({ "NtResumeThread", 0 });
	str_idx_map.insert({ "NtTerminateThread", 0 });
	str_idx_map.insert({ "RtlCreateUserThread", 0 });
	str_idx_map.insert({ "NtQueueApcThread", 0 });
	str_idx_map.insert({ "_vbe6_StringConcat", 0 });
	str_idx_map.insert({ "vbe6_CreateObject", 262144 });
	str_idx_map.insert({ "vbe6_GetObject", 0 });
	str_idx_map.insert({ "vbe6_GetIDFromName", 0 });
	str_idx_map.insert({ "vbe6_CallByName", 0 });
	str_idx_map.insert({ "vbe6_Invoke", 0 });
	str_idx_map.insert({ "vbe6_Shell", 0 });
	str_idx_map.insert({ "vbe6_Import", 0 });
	str_idx_map.insert({ "vbe6_Open", 0 });
	str_idx_map.insert({ "vbe6_Print", 0 });
	str_idx_map.insert({ "vbe6_Close", 0 });
	str_idx_map.insert({ "WSAStartup", 0 });
	str_idx_map.insert({ "gethostbyname", 0 });
	str_idx_map.insert({ "socket", 0 });
	str_idx_map.insert({ "getsockname", 0 });
	str_idx_map.insert({ "connect", 0 });
	str_idx_map.insert({ "send", 0 });
	str_idx_map.insert({ "sendto", 0 });
	str_idx_map.insert({ "recv", 0 });
	str_idx_map.insert({ "recvfrom", 0 });
	str_idx_map.insert({ "accept", 0 });
	str_idx_map.insert({ "bind", 0 });
	str_idx_map.insert({ "listen", 0 });
	str_idx_map.insert({ "select", 0 });
	str_idx_map.insert({ "setsockopt", 0 });
	str_idx_map.insert({ "ioctlsocket", 0 });
	str_idx_map.insert({ "closesocket", 0 });
	str_idx_map.insert({ "shutdown", 0 });
	str_idx_map.insert({ "WSAAccept", 0 });
	str_idx_map.insert({ "WSARecv", 0 });
	str_idx_map.insert({ "WSARecvFrom", 0 });
	str_idx_map.insert({ "WSASend", 0 });
	str_idx_map.insert({ "WSASendTo", 0 });
	str_idx_map.insert({ "WSASocketA", 0 });
	str_idx_map.insert({ "WSASocketW", 0 });
	str_idx_map.insert({ "WSAConnect", 0 });
	str_idx_map.insert({ "ConnectEx", 0 });
	str_idx_map.insert({ "TransmitFile", 0 });
	str_idx_map.insert({ "IWbemServices_ExecQuery", 786432 });
	str_idx_map.insert({ "IWbemServices_ExecQueryAsync", 786432 });
	str_idx_map.insert({ "IWbemServices_ExecMethod", 0 });
	str_idx_map.insert({ "IWbemServices_ExecMethodAsync", 786432 });
	str_idx_map.insert({ "SetUnhandledExceptionFilter", 0 });
	str_idx_map.insert({ "RtlAddVectoredExceptionHandler", 0 });
	str_idx_map.insert({ "RtlAddVectoredContinueHandler", 0 });
	str_idx_map.insert({ "RtlRemoveVectoredExceptionHandler", 0 });
	str_idx_map.insert({ "RtlRemoveVectoredContinueHandler", 0 });
	str_idx_map.insert({ "RtlDispatchException", 0 });
	str_idx_map.insert({ "_RtlRaiseException", 0 });
	str_idx_map.insert({ "_NtRaiseException", 0 });
	str_idx_map.insert({ "FindResourceA", 12 });
	str_idx_map.insert({ "FindResourceW", 786432 });
	str_idx_map.insert({ "FindResourceExA", 12 });
	str_idx_map.insert({ "FindResourceExW", 786432 });
	str_idx_map.insert({ "LoadResource", 0 });
	str_idx_map.insert({ "SizeofResource", 0 });
	str_idx_map.insert({ "GetSystemMetrics", 0 });
	str_idx_map.insert({ "GetCursorPos", 0 });
	str_idx_map.insert({ "GetComputerNameA", 2 });
	str_idx_map.insert({ "GetComputerNameW", 131072 });
	str_idx_map.insert({ "GetUserNameA", 2 });
	str_idx_map.insert({ "GetUserNameW", 131072 });
	str_idx_map.insert({ "GetUserNameExA", 4 });
	str_idx_map.insert({ "GetUserNameExW", 262144 });
	str_idx_map.insert({ "EnumWindows", 0 });
	str_idx_map.insert({ "GetDiskFreeSpaceW", 131072 });
	str_idx_map.insert({ "GetDiskFreeSpaceExW", 131072 });
	str_idx_map.insert({ "WriteConsoleA", 0 });
	str_idx_map.insert({ "WriteConsoleW", 0 });
	str_idx_map.insert({ "SHGetSpecialFolderLocation", 0 });
	str_idx_map.insert({ "SHGetFolderPathW", 2097152 });
	str_idx_map.insert({ "LookupAccountSidW", 2752512 });
	str_idx_map.insert({ "ReadCabinetState", 0 });
	str_idx_map.insert({ "UuidCreate", 0 });
	str_idx_map.insert({ "GetTimeZoneInformation", 0 });
	str_idx_map.insert({ "GetFileVersionInfoSizeW", 131072 });
	str_idx_map.insert({ "GetFileVersionInfoSizeExW", 262144 });
	str_idx_map.insert({ "GetFileVersionInfoW", 131072 });
	str_idx_map.insert({ "GetFileVersionInfoExW", 262144 });
	str_idx_map.insert({ "NotifyBootConfigStatus", 0 });
	str_idx_map.insert({ "TaskDialog", 12058624 });
	str_idx_map.insert({ "CreateActCtxW", 0 });
	str_idx_map.insert({ "RegisterHotKey", 0 });
	str_idx_map.insert({ "SetStdHandle", 0 });
	str_idx_map.insert({ "NetGetJoinInformation", 393216 });
	str_idx_map.insert({ "NetUserGetInfo", 393216 });
	str_idx_map.insert({ "NetUserGetLocalGroups", 393216 });
	str_idx_map.insert({ "NetShareEnum", 131072 });
	str_idx_map.insert({ "CreateProcessInternalW", 34340864 });
	str_idx_map.insert({ "ShellExecuteExW", 0 });
	str_idx_map.insert({ "ReadProcessMemory", 0 });
	str_idx_map.insert({ "WriteProcessMemory", 0 });
	str_idx_map.insert({ "system", 0 });
	str_idx_map.insert({ "CreateToolhelp32Snapshot", 0 });
	str_idx_map.insert({ "Process32FirstW", 0 });
	str_idx_map.insert({ "Process32NextW", 0 });
	str_idx_map.insert({ "Module32FirstW", 0 });
	str_idx_map.insert({ "Module32NextW", 0 });
	str_idx_map.insert({ "NtCreateKey", 0 });
	str_idx_map.insert({ "NtOpenKey", 0 });
	str_idx_map.insert({ "NtOpenKeyEx", 0 });
	str_idx_map.insert({ "NtRenameKey", 0 });
	str_idx_map.insert({ "NtReplaceKey", 0 });
	str_idx_map.insert({ "NtEnumerateKey", 0 });
	str_idx_map.insert({ "NtEnumerateValueKey", 0 });
	str_idx_map.insert({ "NtSetValueKey", 0 });
	str_idx_map.insert({ "NtQueryValueKey", 0 });
	str_idx_map.insert({ "NtQueryMultipleValueKey", 0 });
	str_idx_map.insert({ "NtDeleteKey", 0 });
	str_idx_map.insert({ "NtDeleteValueKey", 0 });
	str_idx_map.insert({ "NtLoadKey", 0 });
	str_idx_map.insert({ "NtLoadKey2", 0 });
	str_idx_map.insert({ "NtLoadKeyEx", 0 });
	str_idx_map.insert({ "NtQueryKey", 0 });
	str_idx_map.insert({ "NtSaveKey", 0 });
	str_idx_map.insert({ "NtSaveKeyEx", 0 });
	str_idx_map.insert({ "CreateThread", 0 });
	str_idx_map.insert({ "CreateRemoteThread", 0 });
	str_idx_map.insert({ "CreateRemoteThreadEx", 0 });
	str_idx_map.insert({ "Thread32First", 0 });
	str_idx_map.insert({ "Thread32Next", 0 });
	str_idx_map.insert({ "URLDownloadToFileW", 786432 });
	str_idx_map.insert({ "InternetCrackUrlA", 2 });
	str_idx_map.insert({ "InternetCrackUrlW", 131072 });
	str_idx_map.insert({ "InternetOpenA", 26 });
	str_idx_map.insert({ "InternetOpenW", 1703936 });
	str_idx_map.insert({ "InternetConnectA", 52 });
	str_idx_map.insert({ "InternetConnectW", 3407872 });
	str_idx_map.insert({ "InternetOpenUrlA", 12 });
	str_idx_map.insert({ "InternetOpenUrlW", 786432 });
	str_idx_map.insert({ "InternetQueryOptionA", 0 });
	str_idx_map.insert({ "InternetSetOptionA", 0 });
	str_idx_map.insert({ "HttpOpenRequestA", 124 });
	str_idx_map.insert({ "HttpOpenRequestW", 8126464 });
	str_idx_map.insert({ "HttpSendRequestA", 4 });
	str_idx_map.insert({ "HttpSendRequestW", 262144 });
	str_idx_map.insert({ "InternetReadFile", 0 });
	str_idx_map.insert({ "InternetWriteFile", 0 });
	str_idx_map.insert({ "InternetCloseHandle", 0 });
	str_idx_map.insert({ "InternetGetConnectedState", 0 });
	str_idx_map.insert({ "InternetGetConnectedStateExA", 4 });
	str_idx_map.insert({ "InternetGetConnectedStateExW", 262144 });
	str_idx_map.insert({ "InternetSetStatusCallback", 0 });
	str_idx_map.insert({ "DeleteUrlCacheEntryA", 2 });
	str_idx_map.insert({ "DeleteUrlCacheEntryW", 131072 });
	str_idx_map.insert({ "DnsQuery_A", 0 });
	str_idx_map.insert({ "DnsQuery_UTF8", 0 });
	str_idx_map.insert({ "DnsQuery_W", 0 });
	str_idx_map.insert({ "getaddrinfo", 0 });
	str_idx_map.insert({ "GetAddrInfoW", 393216 });
	str_idx_map.insert({ "GetInterfaceInfo", 0 });
	str_idx_map.insert({ "GetAdaptersInfo", 0 });
	str_idx_map.insert({ "GetAdaptersAddresses", 0 });
	str_idx_map.insert({ "HttpQueryInfoA", 0 });
	str_idx_map.insert({ "ObtainUserAgentString", 4 });
	str_idx_map.insert({ "GetBestInterfaceEx", 0 });
	str_idx_map.insert({ "WNetGetProviderNameW", 4 });
	str_idx_map.insert({ "CreateJobObjectW", 4 });
	str_idx_map.insert({ "SetInformationJobObject", 0 });
	str_idx_map.insert({ "AssignProcessToJobObject", 0 });
	str_idx_map.insert({ "FindWindowA", 6 });
	str_idx_map.insert({ "FindWindowW", 393216 });
	str_idx_map.insert({ "FindWindowExA", 24 });
	str_idx_map.insert({ "FindWindowExW", 1572864 });
	str_idx_map.insert({ "GetForegroundWindow", 12 });
	str_idx_map.insert({ "MessageBoxTimeoutW", 786432 });
	str_idx_map.insert({ "DrawTextExA", 4 });
	str_idx_map.insert({ "DrawTextExW", 262144 });
	str_idx_map.insert({ "LoadStringA", 8 });
	str_idx_map.insert({ "LoadStringW", 524288 });
	str_idx_map.insert({ "_CreateWindowExA", 12 });
	str_idx_map.insert({ "_CreateWindowExW", 786432 });
	str_idx_map.insert({ "_DialogBoxIndirectParamA", 0 });
	str_idx_map.insert({ "_DialogBoxIndirectParamW", 0 });

}

#endif // HEADER_NAME_H