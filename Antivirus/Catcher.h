#pragma once
#include <iostream>
#include <filesystem>
#include <winternl.h>
#include <tlhelp32.h>

using namespace std;
using namespace std::filesystem;

class Catcher {

private:
	// ���� �� AppData, {User} � WindowsServices
	path appdata = temp_directory_path()
		.parent_path()
		.parent_path()
		.parent_path();
	path user = appdata.parent_path();
	path windowsServices = appdata.append("Roaming").append("WindowsServices");

	// smss virus path
	const path smssVirusPath = user.append("smss.exe");


	// vbs virus
	path helperVbsPath = path(windowsServices); //= path(windowsServices.string().append("\\helper.vbs"));
	path installerVbsPath = path(windowsServices); // = path(windowsServices.string().append("\\installer.vbs"));
	path movemenoregVbsPath = path(windowsServices); // = path(windowsServices.string().append("\\movemenoreg.vbs"));
	path WindowsServicesExePath = path(windowsServices); // = path(windowsServices.string().append("\\WindowsServices.exe"));

public: Catcher() {
	helperVbsPath.append("helper.vbs");
	installerVbsPath.append("installer.vbs");
	movemenoregVbsPath.append("movemenoreg.vbs");
	WindowsServicesExePath.append("WindowsServices.exe");
	while (true) {
		detectProcesses(); // ���������� � ���������� ���������.
		Sleep(2000); // ��� 2 �������, ����� ��������������, ��� �������� ����������.
		deleteViruses();   // �������� �������.
		Sleep(10000); // ��� 10 ������. ���������� ���� ����� ����� =)
	}
}
	  // ������� �������� �����, ���� ��� ����������.
public: void deleteViruses() {
	remove(smssVirusPath.string());
	remove(helperVbsPath.string());
	remove(installerVbsPath.string());
	remove(movemenoregVbsPath.string());
	remove(WindowsServicesExePath.string());
}

	  // ������ ����� �� ������. ������ ������ � ������� ��������� ������, ��� ��� ��� ��������.
	  // https://espresso3389.hatenablog.com/entry/20080723/1216815501
public: void detectProcesses() {
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
				// ������ ����� �������������. ����������� ���������.
				string path;
				for (int i = 0; i < (sizeof(buffer) / sizeof(buffer[0])); i++) {
					path += buffer[i];
				}

				// ��������� ����� � ���������� �������� � ���������.
				size_t smssExists = path.find(smssVirusPath.string());
				size_t helperVBSExists = path.find(helperVbsPath.string());
				size_t installerVBSExists = path.find(installerVbsPath.string());
				size_t movemenoregVBSExists = path.find(movemenoregVbsPath.string());
				size_t WindowsServicesExeExists = path.find(WindowsServicesExePath.string());

				// ���� �������, ��������.
				if (string::npos != smssExists || string::npos != helperVBSExists || string::npos != installerVBSExists ||
					string::npos != movemenoregVBSExists || string::npos != WindowsServicesExeExists) {
					HANDLE killProcess = OpenProcess(PROCESS_TERMINATE, 0, pe.th32ProcessID);
					TerminateProcess(killProcess, 1);
					CloseHandle(killProcess);
				}
			}
			CloseHandle(hProcess);
		}
	} while (Process32Next(hSnapshot, &pe));
	CloseHandle(hSnapshot);
}
	  // ������ ����� �� ������. ������ ������ � ������� ��������� ������, ��� ��� ��� ��������.
	  // https://espresso3389.hatenablog.com/entry/20080723/1216815501
private: DWORD GetRemoteCommandLineW(HANDLE hProcess, LPWSTR pszBuffer, UINT bufferLength)
{
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