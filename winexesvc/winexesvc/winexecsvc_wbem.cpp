#include "stdafx.h"
#include <windows.h>
#include <aclapi.h>
#include <userenv.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include <wbemcli.h>
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

#include "winexecsvc_wbem.h"

WinExeSvcWbem::WinExeSvcWbem()
    : m_namespace(BSTR(L"\\\\.\\ROOT\\CIMV2"))
    , m_prefix(0)
{
}

static bool write_strvalue(FILE *file, BSTR str)
{
    if (!file) return false;
    int wlen = lstrlenW(str);
    if (wlen == 0) return true;
    int utf8len = WideCharToMultiByte(CP_UTF8, 0, str, wlen, NULL, 0, NULL, NULL);
    if (utf8len == 0) return false;
    char *utf8 = (char*) malloc(utf8len);
    if (!utf8) return false;
    utf8len = WideCharToMultiByte(CP_UTF8, 0, str, wlen, utf8, utf8len, NULL, NULL);
    if (utf8len == 0) return false;
    fwrite(utf8, 1, utf8len, file);
    free(utf8);
    return true;
}

void WinExeSvcWbem::print_strvalue(FILE* strm, IWbemClassObject *pclsObj, LPCWSTR name
		, LPCWSTR title, LPCWSTR sufix)
{
	VARIANT vtProp;
	VariantInit(&vtProp);
	HRESULT hr = pclsObj->Get(name, 0, &vtProp, 0, 0);
	if (SUCCEEDED(hr)) {
		if (VT_BSTR == VARENUM(vtProp.vt)) {
            fwprintf(strm, L"      \"%ls\" : \"", title);
            write_strvalue(strm, vtProp.bstrVal);
			fwprintf(strm, L"\"%ls\n", sufix);
		} else {
			fwprintf(strm, L"      \"%ls\" : \"\"%ls\n", title, sufix);
		}
	} else {
		fwprintf(strm, L"      \"%ls\" : null%ls\n", title, sufix);
		fwprintf(strm, L"      \"__error_%ls\" : %lx%ls\n", title, hr, sufix);
	}
	VariantClear(&vtProp);
}

void WinExeSvcWbem::print_strvalue(FILE* strm, HKEY key, LPCWSTR name
		, LPCWSTR title, LPCWSTR sufix)
{
    WCHAR value[128] = {};
    WCHAR* xvalue = value;
    DWORD cbData = 128;
    LSTATUS status = RegGetValueW(key, NULL, name, RRF_RT_REG_SZ, NULL, (PVOID)value, &cbData);
    if (ERROR_MORE_DATA == status) {
        xvalue = (WCHAR*)malloc(cbData * sizeof(WCHAR));
        status = RegGetValueW(key, NULL, name, RRF_RT_REG_SZ, NULL, (PVOID)xvalue, &cbData);
    }
	if (ERROR_SUCCESS == status) {
        fwprintf(strm, L"      \"%ls\" : \"", title);
        write_strvalue(strm, xvalue);
        fwprintf(strm, L"\"%ls\n", sufix);
	} else {
		fwprintf(strm, L"      \"%ls\" : null%ls\n", title, sufix);
	}
    if (value != xvalue)
        free(xvalue);
}

HKEY WinExeSvcWbem::open_registry(HKEY root, ...)
{
    LSTATUS status = ERROR_SUCCESS;
    HKEY current = root;
    va_list args;
    va_start(args, root);
    LPCWSTR arg = va_arg(args, LPCWSTR);
    while (NULL != arg) {
        status = RegOpenKeyW(root, arg, &current);
        RegCloseKey(root);
        root = current;
        if (ERROR_SUCCESS != status) {
            current = NULL;
            break;
        }
        arg = va_arg(args, LPCWSTR);
    }
    va_end(args);
    return current;
}

void WinExeSvcWbem::exec(FILE* strmout, FILE* strmerr, BSTR query) {
	fprintf(strmout, "[");
	HRESULT hr = exec0(strmout, strmerr, query);
    if (SUCCEEDED(hr))
        fprintf(strmout, "\n  ");
	fprintf(strmout, "],\n");
	if (FAILED(hr)) {
		fprintf(strmout, "  \"error\" : \"%lx\"", hr);
	} else {
		fprintf(strmout, "  \"error\" : null");
	};
	CoUninitialize();
}

HRESULT WinExeSvcWbem::exec0(FILE* strmout, FILE* strmerr, BSTR query) {
	HRESULT hr = S_OK;
	do {
		hr = CoInitialize(NULL);
		if (FAILED(hr)) {
			fprintf(strmerr, "error: \"CoInitialize failed\" %lx\n");
			break;
		}
		IWbemLocator *pLoc = NULL;
		hr = CoCreateInstance(CLSID_WbemLocator, 0,
			CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc);
		//ComPtr<int> ptr(__uuidof());
		if (FAILED(hr)) {
			fprintf(strmerr, "error: \"WbemLocator failed\" %lx\n", hr);
			break;
		}
		IWbemServices *pSvc = NULL;
		hr = pLoc->ConnectServer(
			m_namespace,  //namespace
			NULL,       // User name
			NULL,       // User password
			0,         // Locale
			NULL,     // Security flags
			0,         // Authority
			0,        // Context object
			&pSvc);   // IWbemServices proxy
		if (FAILED(hr)) {
			fprintf(strmerr, "error: \"ConnectServer failed\" %lx\n", hr);
			break;
		}
		hr = CoSetProxyBlanket(
		   pSvc,                        // Indicates the proxy to set
		   RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		   RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		   NULL,                        // Server principal name
		   RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
		   RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		   NULL,                        // client identity
		   EOAC_NONE                    // proxy capabilities
		);

		if (FAILED(hr)) {
			fprintf(strmerr, "error: \"CoSetProxyBlanket failed\" %lx\n", hr);
			break;
		}
		IEnumWbemClassObject *pEnum = NULL;
		hr = pSvc->ExecQuery(BSTR(L"WQL"), query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnum);

		if (FAILED(hr)) {
			fprintf(strmerr, "error: \"ExecQuery failed\" %lx\n", hr);
			break;
		}
		IWbemClassObject *pclsObj = NULL;
		ULONG uReturn = 0;

		if (pEnum) {
			do {
				HRESULT hr = pEnum->Next(WBEM_INFINITE, 1,
					&pclsObj, &uReturn);

				if(FAILED(hr) || (0 == uReturn))
					break;
				print_object(strmout, strmerr, pclsObj);
				pclsObj->Release();
			} while (true);
		}
	} while (false);
	CoUninitialize();
    return hr;
}

void WinExeSvcWbem::print_header(FILE* strmout)
{
	if (0 != m_prefix)
		fprintf(strmout, "%c", m_prefix);
	fprintf(strmout, "\n    {\n");
}

void  WinExeSvcWbem::print_footer(FILE* strmout)
{
	fprintf(strmout, "    }");
	m_prefix = ',';
}