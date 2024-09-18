// winexesvc.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "winexesvc.h"
#include "winexecsvc_wbem.h"

extern "C"
{
int winexesvc_product(int, char *[])
{
	class WinExeSvcWbem_product : public WinExeSvcWbem
	{
	protected:
		virtual void print_object(FILE* strm, FILE* err, IWbemClassObject *pclsObj) {
			print_header(strm);
			print_strvalue(strm, pclsObj, L"Name", L"name", L",");
			print_strvalue(strm, pclsObj, L"Version", L"version", L",");
			print_strvalue(strm, pclsObj, L"Language", L"language", L",");
			print_strvalue(strm, pclsObj, L"InstallDate", L"installDate", L",");
			print_strvalue(strm, pclsObj, L"IdentifyingNumber", L"identifyingNumber", L"");
			print_footer(strm);
		}
	} product;
	product.exec(stdout, stderr, BSTR(L"SELECT Name, Version, Language, InstallDate, IdentifyingNumber from Win32_Product"));
	return 0;
}
}

