#pragma once
#include <iostream>
#include <filesystem>
#include <winternl.h>
#include <tlhelp32.h>
#include "PreparedPaths.h"

using namespace std;
using namespace std::filesystem;

class Catcher {

private:
	// Пути вирусов
	path smssVirusPath = PreparedPaths::getUser();
	path windowsServicesPath = PreparedPaths::getAppData(); // Место скопление USB-VIRUS'а.

	// Лист путей вирусов
	list<path> listOfPaths;

public:
	Catcher() {
		smssVirusPath.append("smss.exe");
		windowsServicesPath.append("Roaming").append("WindowsServices");
		
		listOfPaths = { smssVirusPath, windowsServicesPath };
		// Для добавления можно как создать переменную и добавить в лист 
		// или инициализируем на месте через path("путь\\до\\файла_или_папки")

		while (true) {
			detectProcesses(); // Нахождение, отключение и удаление процессов.
			Sleep(1000);
			deleteViruses();   // Дополнительный проход по путям, чтобы удостовериться в удалении.
			Sleep(1000);
		}
	}
	// Удаляет вирусные файлы, если они существуют.
	// Проверка try-catch используется, чтобы программа не вылетала, если процесс не успел выключиться.
	void deleteViruses() {
		for (path path : listOfPaths) {
			try {
				remove(path.string());
				Sleep(200); // В случае большого количества путей возможны сильные нагрузки на систему.
			}
			catch (...) {
				throw;
			}
		}
	}

	// Удаляет все, что находится на переданном пути.
	// Проверка try-catch используется, чтобы программа не вылетала, если процесс не успел выключиться.
	void deleteVirus(path path) {
		try {
			remove(path.string());
			Sleep(200); // В случае большого количества путей возможны сильные нагрузки на систему.
		}
		catch (...) {
			throw;
		}
	}

	// Темная магия от японца. Низкий поклон и сильное нежелание читать, так как оно работает.
	// https://espresso3389.hatenablog.com/entry/20080723/1216815501
	void detectProcesses() {
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			return;
		}
		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(pe);
		if (!Process32First(hSnapshot, &pe))
		{
			CloseHandle(hSnapshot);
			return;
		}
		do
		{
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
			if (hProcess)
			{
				WCHAR buffer[MAX_PATH];
				buffer[0] = 0;

				if (GetRemoteCommandLineW(hProcess, buffer, MAX_PATH)) {
					// Темная магия заканчивается. Просыпаются рукожопии.
					string args;
					for (int i = 0; i < (sizeof(buffer) / sizeof(buffer[0])); i++) {
						args += buffer[i];
					}

					// Сравнение путей в аргументах процесса с вирусными.
					for (path path : listOfPaths) {
						size_t pathExists = args.find(path.string());
						// Если совпало, вырубаем.
						if (string::npos != pathExists) {
							HANDLE killProcess = OpenProcess(PROCESS_TERMINATE, 0, pe.th32ProcessID);
							if (TerminateProcess(killProcess, 1) && CloseHandle(killProcess)) {
								//Sleep(1000);
								deleteVirus(path);
							}
						}
					}
				}
				CloseHandle(hProcess);
			}
		} while (Process32Next(hSnapshot, &pe));
		CloseHandle(hSnapshot);
	}
	
private:
	// Темная магия от японца. Низкий поклон и сильное нежелание читать, так как оно работает.
	// https://espresso3389.hatenablog.com/entry/20080723/1216815501
	DWORD GetRemoteCommandLineW(HANDLE hProcess, LPWSTR pszBuffer, UINT bufferLength) {
		struct RTL_USER_PROCESS_PARAMETERS_I
		{
			BYTE Reserved1[16];
			PVOID Reserved2[10];
			UNICODE_STRING ImagePathName;
			UNICODE_STRING CommandLine;
		};

		struct PEB_INTERNAL
		{
			BYTE Reserved1[2];
			BYTE BeingDebugged;
			BYTE Reserved2[1];
			PVOID Reserved3[2];
			struct PEB_LDR_DATA* Ldr;
			RTL_USER_PROCESS_PARAMETERS_I* ProcessParameters;
			BYTE Reserved4[104];
			PVOID Reserved5[52];
			struct PS_POST_PROCESS_INIT_ROUTINE* PostProcessInitRoutine;
			BYTE Reserved6[128];
			PVOID Reserved7[1];
			ULONG SessionId;
		};

		typedef NTSTATUS(NTAPI* NtQueryInformationProcessPtr)(
			IN HANDLE ProcessHandle,
			IN PROCESSINFOCLASS ProcessInformationClass,
			OUT PVOID ProcessInformation,
			IN ULONG ProcessInformationLength,
			OUT PULONG ReturnLength OPTIONAL);

		typedef ULONG(NTAPI* RtlNtStatusToDosErrorPtr)(NTSTATUS Status);

		// Locating functions
		HINSTANCE hNtDll = GetModuleHandleW(L"ntdll.dll");
		NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hNtDll, "NtQueryInformationProcess");
		RtlNtStatusToDosErrorPtr RtlNtStatusToDosError = (RtlNtStatusToDosErrorPtr)GetProcAddress(hNtDll, "RtlNtStatusToDosError");

		if (!NtQueryInformationProcess || !RtlNtStatusToDosError)
		{
			printf("Functions cannot be located.\n");
			return 0;
		}

		// Get PROCESS_BASIC_INFORMATION
		PROCESS_BASIC_INFORMATION pbi;
		ULONG len;
		NTSTATUS status = NtQueryInformationProcess(
			hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len);
		SetLastError(RtlNtStatusToDosError(status));
		if (NT_ERROR(status) || !pbi.PebBaseAddress)
		{
			printf("NtQueryInformationProcess(ProcessBasicInformation) failed.\n");
			return 0;
		}

		// Read PEB memory block
		SIZE_T bytesRead = 0;
		PEB_INTERNAL peb;
		if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead))
		{
			printf("Reading PEB failed.\n");
			return 0;
		}

		// Obtain size of commandline string
		RTL_USER_PROCESS_PARAMETERS_I upp;
		if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead))
		{
			printf("Reading USER_PROCESS_PARAMETERS failed.\n");
			return 0;
		}

		if (!upp.CommandLine.Length)
		{
			printf("Command line length is 0.\n");
			return 0;
		}

		// Check the buffer size
		DWORD dwNeedLength = (upp.CommandLine.Length + 1) / sizeof(wchar_t) + 1;
		if (bufferLength < dwNeedLength)
		{
			// printf("Not enough buffer.\n");
			return dwNeedLength;
		}

		// Get the actual command line
		pszBuffer[dwNeedLength - 1] = L'\0';
		if (!ReadProcessMemory(hProcess, upp.CommandLine.Buffer, pszBuffer, upp.CommandLine.Length, &bytesRead))
		{
			printf("Reading command line failed.\n");
			return 0;
		}

		return bytesRead / sizeof(wchar_t);
	}
};