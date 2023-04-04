#pragma once
#include <iostream>
#include <filesystem>

using namespace std::filesystem;

class PreparedPaths {
private:
	static inline path appdata = temp_directory_path()
		.parent_path().parent_path().parent_path();  // Path >> {Disk}:\\Users\\{User}\\AppData
	static inline  path user = appdata.parent_path();              // Path >> {Disk}:\\Users\\{User}
	static inline  path disk = user.parent_path().parent_path();   // Path >> {Disk}:\\

public:
	static path getDisk() {
		return disk;
	}

	static path getUser() {
		return user;
	}
	
	static path getAppData() {
		return appdata;
	}
};

