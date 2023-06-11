#include "common.h"
#include "API/Vorpal.h"
#include "HWID/HWID.h"
#include "Utilities/Memory/Integrity.h"
#include "Utilities/Utils.h"

Vorpal vorpal("YOUR_BRAND_ID");

std::string username, password;
bool login = false;

void BrandLogin() {
    vorpal.login(username, password);
    auto time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto delta = (time - vorpal.LoginInfo.Time);
    const float min = -5;
    if (delta <= 60 && delta >= min) {
        if (vorpal.LoginInfo.Error.empty() && vorpal.LoginInfo.Result) {
            if (vorpal.LoginInfo.Username == username) {
                //Successful Login (:
                printf(strEnc("Successfull Login\n"));

                login = true;
                return;
            }
            else {
                printf(strEnc("Invalid Username\n"));
                return;
            }
        }
        else {
            printf((vorpal.LoginInfo.Error + strEnc("\n")).c_str());
            return;
        }
    }
    else {
        printf(strEnc("Took longer than 60 seconds to do this request...\n"));
        return;
    }
    return;
}

void check() {
    static VorpalAPI::Memory::Integ::Integrity integrity;

    integrity.Checksum();
    integrity.ChecksumFromDisk();

    hash_Sleep(3000);
}

int main() {
    //TODO: Fix this
    //VorpalAPI::Memory::Threads::GetThreadPool()->Initialize(1); //Register 1 thread space(s)
    //Can cause false positives if memory is modified after the thread... should probably just scan for .text as that's where our vorpalApi is in...
    //VorpalAPI::Memory::Threads::GetThreadPool()->RegisterThread(strEnc("INT"), check);

    username = "username";
    password = "password";

    //Wait for thread to be finished executing...
    std::thread(BrandLogin).join();
 
    //Double check login results incase of people trying to byte patch login boolean.
    if (login && vorpal.LoginInfo.Result && vorpal.LoginInfo.Error.empty()) {
        //Check if user has a key
        if (!vorpal.LoginInfo.Key.empty()) {
            //Server ONLY sends active running keys, so once they expire they'll nolonger be send in the request.
            LicenseKey licenseInfo;
            for (size_t i = 0; i < vorpal.LoginInfo.Key.size(); i++) {
                auto key = vorpal.LoginInfo.Key[i];

                //Look if user has this specific application redeemed.
                if (strstr(key.ApplicationName.c_str(), strEnc("test"))) {
                    //User has a license to our application
                    licenseInfo = vorpal.LoginInfo.Key[i];
                    break;
                }
            }

            vorpal.GetApplication(licenseInfo.AppId);
            if (vorpal.AppInfo.Error.empty()) {
                //If Application doesn't require a update (Version check)
                if (vorpal.AppInfo.Version != strEnc("1")) {
                    //If Application is not in maintenance or developer mode
                    if (!vorpal.AppInfo.Maintenance && !vorpal.AppInfo.Developer) {
                        //Login request to application
                        vorpal.loginApplication(licenseInfo.AppId);
                        if (vorpal.LoginAppInfo.Error.empty()) {
                            if (vorpal.LoginAppInfo.HashedID == vorpal.LoginInfo.HashedID && vorpal.LoginAppInfo.Username == vorpal.LoginInfo.Username) {
                                //HWID is also checked on server, if hwid mismatches in the request send to server, it will throw a error and have results also be false.
                                if (vorpal.LoginAppInfo.HWID == VorpalAPI::HWID::grabHWID()) {
                                    if (vorpal.LoginAppInfo.Result) {
                                        printf(strEnc("Successfully logged into the application...\n"));

                                       
                                    }
                                    else {
                                        printf(strEnc("Failed to login..\n"));
                                        return 0;
                                    }
                                }
                                else {
                                    printf(strEnc("Mismatches hwid..\n"));
                                    return 0;
                                }
                            }
                            else {
                                printf(strEnc("... technically impossible to happen, how?\n"));
                                return 0;
                            }
                        }
                        else {
                            printf((vorpal.LoginAppInfo.Error + strEnc("\n")).c_str());
                            return 0;
                        }
                    }
                    else {
                        printf(strEnc("Application is currently in maintenance or developer mode.\n"));
                        return 0;
                    }
                }
                else {
                    printf(strEnc("Outdated application... please update\n"));
                    return 0;
                }
            }
            else {
                printf((vorpal.AppInfo.Error + strEnc("\n")).c_str());
                return 0;
            }
        }
        else {
            printf(strEnc("User has no active keys redeemed...\n"));
            return 0;
        }
    }

    while (true) {

    }

    return 0;
}

