#include <iostream>
#include <Windows.h>

#include "Scanner.h"

void check_policy()
{
	std::cout << "=============================================================" << std::endl;
	std::cout << "for this function to work, the following settings must be enabled:" << std::endl;
	std::cout << "\"scan all downloaded files and attachments\" in local group policy editor" << std::endl;
	std::cout << "* real-time protection in windows defender security center" << std::endl;

	std::cout << "if one of the above is turned off, you will get this error:" << std::endl;
	std::cout << "failed to scan with error code 0x80070015. reason: the device is not ready." << std::endl;
	std::cout << "=============================================================" << std::endl;
}
void show_usage()
{
	std::cout << "=============================================================" << std::endl;
	std::cout << "AMSI_SCANNER Usage:" << std::endl;
	std::cout << "AMSI_Scanner.exe [file path to scan]" << std::endl;
	std::cout << "example)AMSI_Scanner.exe C:\\windows\\system32\\notepad.exe" << std::endl;
	std::cout << "example)AMSI_Scanner.exe EICAR" << std::endl;
	std::cout << "=============================================================" << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc < 2)
	{
		show_usage();
		return -1;
	}

	Scanner scanner;
	if (true != scanner.initialize())
	{
		std::cout << "initialize failed." << std::endl;
		check_policy();
		return -1;
	}

	bool is_malware = false;
	uint32_t malware_level = 0;

	if (true != scanner.scan_buffer(argv[1],
									is_malware,
									malware_level))
	{
		std::cout << "scanner.scan failed" << std::endl;
		check_policy();
		return -1;
	}

	if (is_malware)
	{
		std::cout << "Result: Malware" << std::endl;
		std::cout << "malware Level: " << malware_level << std::endl;
	}

	return 0;
}
