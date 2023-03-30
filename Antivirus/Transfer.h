#pragma once
#include <iostream>
#include <filesystem>
#include <sys/stat.h>
#include <sys/types.h>

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
	cout << antivirusPath << " " << currentPath << endl;
	if (antivirusPath.compare(currentPath) == 0) {
		return status = true;
	}
	else {
		return status = false;
	}
}
	  // Перемещает антивирус в целевой путь
public: bool move() {
	// Сравнивает путь антивируса и целевой путь
	if (antivirusPath.compare(currentPath) == 0) {
		return status = true;
	}

	// Создает директорию, в случае её отсутствия
	createDirectory();

	// Проверяет существует ли файл
	if (fileExists()) {
		return status = true;
	}

	// Копирует файл в целевой путь
	copy(currentPath, antivirusPath);
	regedit();

	// Запускает программу из целевого пути
	startup();
	return status = true;
}

	  // Создает директорию
private: void createDirectory() {
	create_directory(antivirusPath.parent_path());
}
	   // Возвращает true, если файл существует
private: bool fileExists() {
	struct stat buf;
	return (stat(antivirusPath.string().c_str(), &buf) == 0);
}

private: void regedit() {
	std::wstring progPath = antivirusPath.wstring();
	HKEY hkey = NULL;
	LONG createStatus = RegCreateKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hkey);     
	LONG status = RegSetValueEx(hkey, L"Antivirus", 0, REG_SZ, (BYTE*)progPath.c_str(), (progPath.size() + 1) * sizeof(wchar_t));
}

private: VOID startup()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	// Установка размера структуры
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// Запуск программу
	CreateProcess(antivirusPath.wstring().c_str(),
		NULL, NULL,	NULL, FALSE, 0,NULL, NULL, &si, &pi);
	
	// Закрывает предыдущий процесс и ветки
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

};