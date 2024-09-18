// winexesvc.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "winexesvc.h"
#include "winexecsvc_wbem.h"

extern "C"
{
int winexesvc_computer(int, char *[])
{
	class WinExeSvcWbem_computer : public WinExeSvcWbem
	{
	protected:
		virtual void print_object(FILE* strm, FILE* err, IWbemClassObject *pclsObj) {
			print_header(strm);
			print_strvalue(strm, pclsObj, L"Domain", L"domain", L",");
			print_strvalue(strm, pclsObj, L"Name", L"name", L",");
			HKEY reg = open_registry(HKEY_LOCAL_MACHINE, L"SOFTWARE", L"Microsoft", L"Windows NT", L"CurrentVersion", NULL);
			print_strvalue(strm, reg, L"ProductName", L"caption", L",");
			print_strvalue(strm, reg, L"DisplayVersion", L"version", L",");
			//print_strvalue(strm, reg, L"CurrentVersion", L"api", L",");
			print_strvalue(strm, reg, L"CurrentBuild", L"build", L"");
			print_footer(strm);
		}
	} computer;
	computer.exec(stdout, stderr, BSTR(L"SELECT Domain, Name from Win32_ComputerSystem"));
	return 0;
}
}

