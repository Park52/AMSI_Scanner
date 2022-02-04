#pragma once

#include <iostream>
#include <Windows.h>

#define EICAR L"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

typedef struct stfile_data 
{
	BYTE* file_data;
	ULONG file_size;
} file_data;