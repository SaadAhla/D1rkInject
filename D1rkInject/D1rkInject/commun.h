#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <TlHelp32.h>
#include <time.h>
#include <winternl.h>
#include <winhttp.h>
#include <Psapi.h>


#include "getData.h"
#include "RXstuff.h"
#include "MalStuff.h"


#pragma comment(lib, "winhttp")


#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

