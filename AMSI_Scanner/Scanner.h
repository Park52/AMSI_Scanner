#pragma once

#include <iostream>
#include <Windows.h>
#include <amsi.h>

#include "scan_data.h"

#pragma comment(lib, "amsi.lib")
#pragma comment(lib, "ole32.lib")
class Scanner
{
public:
	Scanner();
	virtual ~Scanner();

public:
	bool initialize();
	void finalize();

public:
	bool scan(_In_ const wchar_t* file_path,
			  _Out_ bool& is_malware,
			  _Out_ uint32_t& malware_level);

	bool scan(_In_ BYTE* data,
			  _In_ ULONG size,
			  _Out_ bool& is_malware,
			  _Out_ uint32_t& malware_level);
private:
	bool get_file_data(_In_ const wchar_t* file_path,
					   _Out_ file_data& data);

private:
	HAMSISESSION _session;
	HAMSICONTEXT _amsi_context;
};