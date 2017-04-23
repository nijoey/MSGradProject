// ConsoleApplication1.cpp : main project file.

#include "stdafx.h"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

#include <tchar.h>
#include <windows.h>
#include <DbgHelp.h>

using namespace std;
using namespace System;

#pragma comment (lib, "dbghelp.lib")

void WriteFullDump(HANDLE hProc,TCHAR* dmpFileName)
{
	const DWORD Flags = MiniDumpWithFullMemory |
		MiniDumpWithFullMemoryInfo |
		MiniDumpWithHandleData |
		MiniDumpWithUnloadedModules |
		MiniDumpWithThreadInfo;

	HANDLE hFile = CreateFile(dmpFileName, GENERIC_ALL, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile)
	{
		std::cerr << _T("Failed to write dump: Invalid dump file");
	}
	else
	{
		BOOL Result = MiniDumpWriteDump(hProc,
			GetProcessId(hProc),
			hFile,
			(MINIDUMP_TYPE)Flags,
			nullptr,
			nullptr,
			nullptr);

		CloseHandle(hFile);

		if (!Result)
		{
			std::cerr << _T("Looks like an error: MiniDumpWriteDump failed");
		}
	}// End if

	return;
}

int main(void)
{
	std::cout << std::endl << "Running Processes" << std::endl;
	HANDLE WINAPI CreateToolhelp32Snapshot(
		DWORD dwFlags,
		DWORD th32ProcessID
	);
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	BOOL WINAPI Process32Next(
		HANDLE hSnapshot,
		LPPROCESSENTRY32 lppe
	);
	PROCESSENTRY32* processInfo = new PROCESSENTRY32;
	processInfo->dwSize = sizeof(PROCESSENTRY32);
	int index = 0;
	if (Process32First(hSnapShot, processInfo) != FALSE)
	{
		TCHAR* dumFileName = new TCHAR[MAX_PATH];
		while (Process32Next(hSnapShot, processInfo) != FALSE)
		{
			std::cout << std::endl << "***********************************************";
			std::cout << std::endl << "\t\t\t" << ++index;
			std::cout << std::endl << "***********************************************";
			std::cout << std::endl << "Parent Process ID: " << processInfo->th32ParentProcessID;
			std::cout << std::endl << "Process ID: " << processInfo->th32ProcessID;
			//std::cout << std::endl << "Process Name: " << processInfo->szExeFile;
			std::printf("\nName %S\n", processInfo->szExeFile);
			std::cout << std::endl << "Current Threads: " << processInfo->cntThreads;
			std::cout << std::endl << "Current Usage: " << processInfo->cntUsage;
			std::cout << std::endl << "Flags: " << processInfo->dwFlags;
			std::cout << std::endl << "Size: " << processInfo->dwSize;
			std::cout << std::endl << "Primary Class Base: " << processInfo->pcPriClassBase;
			std::cout << std::endl << "Default Heap ID: " << processInfo->th32DefaultHeapID;
			std::cout << std::endl << "Module ID: " << processInfo->th32ModuleID;
			if (_tcslen(processInfo->szExeFile) > 0 && 
				(_stprintf(dumFileName, _T("c:\\dmp\\%s.joe"), processInfo->szExeFile))>0) {
				WriteFullDump(hSnapShot, dumFileName);
			}
		}
		delete dumFileName;
	}
	CloseHandle(hSnapShot);
	std::cout << std::endl;
	std::cout << std::endl << "***********************************************";
	std::cout << std::endl << std::endl;
	HANDLE OpenProcess(
		DWORD dwDesiredAccess,  // access flag
		BOOL bInheritHandle,    // handle inheritance option
		DWORD dwProcessId       // process identifier
	);
	int processID;
	std::cout << "Enter ProcessID to suspend the process: ";
	std::cin >> processID;
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	//if (hProcess == NULL)
	//{
	//	std::cout << "Unable to get handle of process: " << processID;
	//	std::cout << "Error is: " << GetLastError();
	//	return 1;
	//}
	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);
	Thread32First(hProcess, &threadEntry);
	do
	{
		ULONG_PTR lowLimit;
		ULONG_PTR highLimit;
		if (threadEntry.th32OwnerProcessID == processID)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
			SuspendThread(hThread);
			GetCurrentThreadStackLimits(&lowLimit, &highLimit);
			CloseHandle(hThread);
		}
	} while (Thread32Next(hProcess, &threadEntry));
	//CloseHandle(hProcess);
	/*std::cout << std::endl << "Priority Class: " << GetPriorityClass(hProcess);
	SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS);
	CloseHandle(hProcess);*/
	std::cout << std::endl << "Enter Process ID to resume that process: ";
	std::cin >> processID;
	//hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, processID);
	hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hProcess == NULL)
	{
		std::cout << "Unable to get handle of process: " << processID;
		std::cout << "Error is: " << GetLastError();
	}
	do
	{
		if (threadEntry.th32OwnerProcessID == processID)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
			ResumeThread(hThread);
			CloseHandle(hThread);
		}
	} while (Thread32Next(hProcess, &threadEntry));
	/*TerminateProcess(hProcess, 0);
	delete processInfo;*/
	std::cout << std::endl << "Enter Process ID to resume that process: ";
	std::cin >> processID;
	return 0;
}
