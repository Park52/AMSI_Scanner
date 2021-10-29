#include "Scanner.h"

Scanner::Scanner()
	: _session(nullptr)
{
	ZeroMemory(&_amsi_context, sizeof(_amsi_context));
}

Scanner::~Scanner()
{
	finalize();
}

bool Scanner::initialize()
{
	bool ret = false;

	HRESULT result = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (S_OK != result)
	{
		std::cout << "CoInitializeEx failed" << std::endl;
		return false;
	}

	do
	{
		result = AmsiInitialize(L"AMSI_Scanner", &_amsi_context);
		if (S_OK != result)
		{
			std::cout << "AmsiInitialize failed" << std::endl;
			break;
		}

		result = AmsiOpenSession(_amsi_context, &_session);
		if (S_OK != result || nullptr == _session)
		{
			std::cout << "AmsiOpenSession failed" << std::endl;
			break;
		}

		ret = true;
	} while (false);

	return ret;
}

void Scanner::finalize()
{
	if (nullptr != _session)
	{
		AmsiUninitialize(_amsi_context);
	}

	CoUninitialize();
}

bool 
Scanner::scan(
	_In_ const wchar_t* file_path, 
	_Out_ bool& is_malware, 
	_Out_ uint32_t& malware_level)
{
	bool ret = false;
	HRESULT result = S_OK;
	AMSI_RESULT scan_result = AMSI_RESULT_CLEAN;
	file_data data;

	do
	{
		if (wcscmp(L"EICAR", file_path) != 0)
		{
			if (true != get_file_data(file_path, data))
			{
				std::cout << "get_file_data failed." << std::endl;
				break;
			}
		}
		else
		{
			data.file_data = (BYTE*)EICAR;
			data.file_size = wcslen(EICAR)* sizeof(wchar_t);
		}

		result = AmsiScanBuffer(_amsi_context,
								data.file_data,
								data.file_size,
								file_path,
								_session,
								&scan_result);
		if (S_OK != result)
		{
			std::cout << "AmsiScanBuffer failed. ErrorNumber:" << result << std::endl;
			break;
		}

		malware_level = scan_result;
		is_malware = AmsiResultIsMalware(scan_result);

		ret = true;
	} while (false);

	if (nullptr != data.file_data)
	{
		VirtualFree(data.file_data, 0, MEM_RELEASE);
	}

	return ret;
}

bool 
Scanner::scan(
	_In_ BYTE* data, 
	_In_ ULONG size, 
	_Out_ bool& is_malware, 
	_Out_ uint32_t& malware_level)
{
	bool ret = false;
	HRESULT result = S_OK;
	AMSI_RESULT scan_result = AMSI_RESULT_CLEAN;

	do
	{
		result = AmsiScanBuffer(_amsi_context,
								data,
								size,
								L"AMSI",
								_session,
								&scan_result);
		if (S_OK != result)
		{
			std::cout << "AmsiScanBuffer failed. ErrorNumber:" << result << std::endl;
			break;
		}

		malware_level = scan_result;
		is_malware = AmsiResultIsMalware(scan_result);

		ret = true;
	} while (false);

	return ret;
}

bool 
Scanner::get_file_data(
	_In_ const wchar_t* file_path,
	_Out_ file_data& data)
{
	bool ret = false;
	HANDLE handle_file = CreateFile(file_path,
									GENERIC_READ,
									0, 
									NULL,
									OPEN_EXISTING,
									FILE_ATTRIBUTE_NORMAL,
									NULL);
	if (INVALID_HANDLE_VALUE == handle_file)
	{
		std::cout << "CreateFile Failed." << std::endl;
		return ret;
	}

	do
	{
		DWORD file_size = GetFileSize(handle_file, NULL);
		if (INVALID_FILE_SIZE == file_size || 0 == file_size)
		{
			std::cout << "GetFileSize Failed." << std::endl;
			break;
		}

		BYTE* buffer = (BYTE*)VirtualAlloc(NULL, 
										   file_size, 
										   MEM_RESERVE | MEM_COMMIT, 
										   PAGE_READWRITE);
		if (nullptr == buffer)
		{
			std::cout << "VirtualAlloc Failed." << std::endl;
			break;
		}

		DWORD read_bytes = 0;
		if (TRUE != ReadFile(handle_file,
							 buffer,
							 file_size,
							 &read_bytes,
							 NULL))
		{
			std::cout << "ReadFile Failed." << std::endl;
			break;
		}

		data.file_data = buffer;
		data.file_size = file_size;

		ret = true;
	} while (false);

	if (INVALID_HANDLE_VALUE != handle_file)
	{
		CloseHandle(handle_file);
	}

	return ret;
}
