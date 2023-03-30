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
	  // Returns antivirus path
public: path getAntivirusPath() {
	return status == true ? antivirusPath : path();
}

	  // Moves current file to the antivirus dir
public: bool move() {
	// Compares program path and target path
	if (antivirusPath.compare(currentPath) == 0) {
		return status = true;
	}

	// Creating directory if not exists
	createDirectory();

	// Checks if file exists
	if (fileExists()) {
		return status = true;
	}

	// Copy file to the antivirus path
	copy(currentPath, antivirusPath);

	// starts program from antivirus path
	startup();
	return status = true;
}

	  // return true if directory created or false if not.
private: bool createDirectory() {
	return create_directory(antivirusPath.parent_path());
}
	   // is file exists
private: bool fileExists() {
	struct stat buf;
	return (stat(antivirusPath.string().c_str(), &buf) == 0);
}

private: VOID startup()
{
	// additional information
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	// set the size of the structures
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// start the program up
	CreateProcess(antivirusPath.wstring().c_str(),   // the path
		NULL,           // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi             // Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
	);
	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

};