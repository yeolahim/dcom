#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <wtypes.h>
#include <wbemcli.h>
#include <winreg.h>

class WinExeSvcWbem
{
public:
    WinExeSvcWbem(BSTR ns) : m_namespace(ns), m_prefix(0) {}
	WinExeSvcWbem();

	void exec(FILE* strmout, FILE* strmerr, BSTR query);
	HRESULT exec0(FILE* strmout, FILE* strmerr, BSTR query);
protected:
    void print_header(FILE* strmout);
    void print_footer(FILE* strmout);
    virtual void print_object(FILE* strm, FILE* err, IWbemClassObject *pclsObj) = 0;
    HKEY open_registry(HKEY root, ...);
	static void print_strvalue(FILE* strm, IWbemClassObject *pclsObj, LPCWSTR name
		, LPCWSTR title, LPCWSTR sufix);
	static void print_strvalue(FILE* strm, HKEY key, LPCWSTR name
		, LPCWSTR title, LPCWSTR sufix);
private:
    BSTR m_namespace;
    char m_prefix;
};