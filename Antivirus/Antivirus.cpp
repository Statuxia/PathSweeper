#include <iostream>
#include <Windows.h>
#include <filesystem>
#include "Transfer.h"
#include "Catcher.h"

using namespace std;
using namespace std::filesystem;

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

	// Проверка перенесен ли антивирус.
	Transfer transfer = Transfer(path(argv[0]));
	if (!transfer.isMoved()) {
		transfer.move();
		return 0;
	}

	// Запуск цикла по проверке на вирусы.
	Catcher();
}


