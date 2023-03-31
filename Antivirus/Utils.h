#pragma once
#include <iostream>
#include <filesystem>

using namespace std;
using namespace std::filesystem;


static bool fileExists(path path) {
	struct stat buf;
	return (stat(path.string().c_str(), &buf) == 0);
}

static bool fileExists(string path) {
	struct stat buf;
	return (stat(path.c_str(), &buf) == 0);
}

