#pragma once

struct Application {
	std::string Error;
	bool Result;
	uint64_t Time;

	std::string Name;
	std::string Domain;
	std::string Version;
	std::string Login;
	std::string Key;
	bool HWID;
	bool Maintenance;
	bool Developer;
	bool AntiDebug;
	bool AntiVM;
};

struct LicenseKey {
	std::string AppId;
	std::string ApplicationName;
	std::string License;
	std::string ExpiryDays;
	uint64_t ExpiryDate;
	int status;
	std::string HWID;
};

struct LoginApplication {
	std::string Error;
	bool Result;
	uint64_t Time;

	std::string HashedID;
	std::string Username;
	std::string Email;
	std::string Status;
	std::string Rank;
	std::string Key;
	std::string HWID;
	uint64_t Expiry;
};

struct Login {
	std::string Error;
	bool Result;
	uint64_t Time;

	std::string HashedID;
	std::string Username;
	std::string Email;
	std::string Status;
	std::string Rank;
	std::vector<LicenseKey> Key;
};

struct Heartbeat {
	std::string Error;
	bool Result;
	uint64_t Time;

	std::string HashedID;
	std::string Username;
	std::string HWID;
};

struct Variable {
	std::string Error;
	bool Result;
	uint64_t Time;
};

class Vorpal {
private:
	std::string GetValorKey();
	std::string username;
	std::string password;
	std::string sessionId;

	inline void CheckHMAC(std::string hmac, std::string body, std::string appId);
	inline void CloseProgram();

public:
	Vorpal(std::string brandId);
	~Vorpal();

	//GetApplication - Get your application settings such as is Anti-debug enabled, antivm, developer mode?, HWID locked? ect.
	void GetApplication(std::string appId);
	//Regist(e)r - ...
	void registr(std::string username, std::string password, std::string email);
	
	//Login - Login request, returns information if it's a valid user with a active license that hasn't expired.
	void login(std::string username, std::string password);

	void loginApplication(std::string appId);
	
	//Redeem License, User has to be logged in to use this API.
	void redeemLicense(std::string licenseKey);

	//Heartbeat to server to make sure connection is still alive & it's a active user.
	void heartbeat(std::string HashedId, std::string appId);

	//Brand 
	void GetBrandVariables();
	void GetBrandVariable(std::string key);
	//Application specific (Require a valid session)
	void GetVariable(std::string key, std::string appId);
	std::string GetFile(std::string key, std::string appId);

	Application AppInfo;
	Login LoginInfo;
	LoginApplication LoginAppInfo;

	Heartbeat HeartbeatInfo;
	Variable VarInfo;
	std::string currentVar;
	//SafeVar<std::string currentVar; //Store last gotten var here


	std::vector<std::pair<std::string, std::string>> Changelogs; //Known changelogs go here, 

	std::string valorId;
	std::string brandId;
};