/**
* Copyright (C) 2023 Vorpal. All rights reserved.
*
* Licensed under the Vorpal Library Software License. You may obtain a copy
* in the file "LICENSE" found at the root of this repository.
*/

#include "common.h"
#include "Vorpal.h"

#include "HTTP/httplib.h"
#include "Utilities/json.hpp"
#include "Utilities/Utils.h"
#include "HWID/HWID.h"

using json = nlohmann::json;

#define VORPALSITE strEnc("https://www.vorpal.gg")

Vorpal::Vorpal(std::string brandId) {
    this->brandId = brandId;
}

Vorpal::~Vorpal() {

}

std::string Vorpal::GetValorKey() {
    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    std::time_t start_time = std::chrono::system_clock::to_time_t(now);
    char timedisplay[100];
    struct tm buf;
    errno_t err = localtime_s(&buf, &start_time);

    if (std::strftime(timedisplay, sizeof(timedisplay), strEnc("%Y"), &buf)) {

    }

    return Utils::sha256(timedisplay);
}

int verifyCallback(int preverify, X509_STORE_CTX* x509_ctx) {
    if (!preverify) {
        return false;
    }

    X509* currentCert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509* cert = X509_STORE_CTX_get0_cert(x509_ctx);

    if (currentCert != cert) {
        return true;
    }

    X509_PUBKEY* pkey = X509_get_X509_PUBKEY(cert);
    if (pkey == nullptr) {
        return false;
    }
    int derPkeyLength = i2d_X509_PUBKEY(pkey, nullptr);
    if (derPkeyLength < 0) {
        return false;
    }
    std::vector<unsigned char> derPkey(derPkeyLength);
    unsigned char* derPkeyData = derPkey.data();
    i2d_X509_PUBKEY(pkey, &derPkeyData);
    auto key = Botan::hex_encode(derPkey);
    std::string expectedpKey = "3059301306072A8648CE3D020106082A8648CE3D03010703420004D0B10A62B2FE1ACB309CF88B4E58D634DF1E5A2D7D40C6A4DCD373CAF9BC69059537C221ECE4ED4387D643F668FF1821D38EAD8843D165C64F44A33150BDF5C7";

    return std::equal(key.begin(), key.end(), expectedpKey.begin(), expectedpKey.end());
}

httplib::Client SecureInit() {
    httplib::Client cli(VORPALSITE);

    //Cert pinning, not always ideal. but does make it more secure, it can change the expectedpKey over time sometimes (due to server getting a new cert) 
    //Hence why it might not be ideal for every user.
#ifdef CERT_PINNING
    //SSL_CTX_set_verify(cli.ssl_context(), SSL_VERIFY_PEER, verifyCallback);
#endif

    const char* cert =
        strEnc("-----BEGIN CERTIFICATE-----\""
            "MIIFJjCCBA6gAwIBAgISBNGsU2m1US5jzB7ojYTkvYkoMA0GCSqGSIb3DQEBCwUA\""
            "MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\""
            "EwJSMzAeFw0yMzAzMDMxOTQyMzZaFw0yMzA2MDExOTQyMzVaMBQxEjAQBgNVBAMT\""
            "CXZvcnBhbC5nZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALoH2kOC\""
            "l1SWHoqAMJFp5/8m7ZCgt72b/FyU1O4zjIVAGgDRqvV6BtT1Z1kuESjkrElGKG/v\""
            "09selEnRa49Ttm2vxMgiwic6vkb9U2CHEUWj8idtMTbWQwcWqq0KrayO2eYX9LaR\""
            "mVzevdlPXokcu5niYpwPiqbETnd5e3Ovn/pcOj/3TY/l5tDbbGJGGvDjqZZ37HHo\""
            "Dccp1djzViyo80hJJRYkhau8ltUJALo86i5rB4AKrN1J3fHCDuaUkMR3dxklTegK\""
            "fl3Uioa+2kfxsBJStMS1RvM9nIofNiQ56ttN/TEFHeM5cBvLzl+XQ+BrmcyLyMbT\""
            "DzPkXxUnxBkfYMMCAwEAAaOCAlIwggJOMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUE\""
            "FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU\""
            "dI23PHu2rb8LlQeXquEHppkt5mswHwYDVR0jBBgwFoAUFC6zF7dYVsuuUAlA5h+v\""
            "nYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vcjMuby5s\""
            "ZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9yZy8wIwYD\""
            "VR0RBBwwGoIJdm9ycGFsLmdngg13d3cudm9ycGFsLmdnMEwGA1UdIARFMEMwCAYG\""
            "Z4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMu\""
            "bGV0c2VuY3J5cHQub3JnMIIBAwYKKwYBBAHWeQIEAgSB9ASB8QDvAHYAtz77JN+c\""
            "Tbp18jnFulj0bF38Qs96nzXEnh0JgSXttJkAAAGGqTZYwQAABAMARzBFAiEA8RBL\""
            "6mgkglHV+jRXGjYVUgQ69U19DReuBmP+BY6EwkMCIDSFHiiwuE728qmve2FxeExw\""
            "0HoqCZ29WVLmZd9f7OKhAHUA6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0G\""
            "vW4AAAGGqTZYtwAABAMARjBEAiBT9wr0kub6runSA71EwDBEpnOAIQOHdEjGOmbO\""
            "TQDmZgIgL8zgw41pAEeSeMa9EwMs4cpLJjCmW+250SBJsZPIytAwDQYJKoZIhvcN\""
            "AQELBQADggEBADcPv7eGJxVYM+4tho0Q8fJXErb39hcRbttOGi+BWGkhbEJ4bWaY\""
            "uhK78+IRo/1ctQzZXHCqzmMuFEYg2NHrnobh5l6AczsDb7KBaN/A2+p3E6yHLikc\""
            "YrzxMg2bPgf7WeAS3W98bFpP69rYZ/hoVGGBjBtAGztMoIADqlJFh9mfjfN41BnZ\""
            "nPFiFnoUFvlCQbQvvidOtaOqq4RJgWR20AUyu9OqhZMtiG6egvSc3hWNAF6t/zgn\""
            "Rqp+YTab71P9Rs0AAJpJ5CBiHbFgou98D0DWtvspLr+oNfAh/Vx4B23mjF32g9zt\""
            "QO8O3IflFVd4xSO2rQXLIoI7ia1M52KAioc=\""
            "-----END CERTIFICATE-----\"");

    X509_STORE* cert_store = X509_STORE_new();

    const char* cert_data_pem = cert;
    cli.set_ca_cert_store(cert_store);
    return cli;
}

inline void Vorpal::CloseProgram() {
    __fastfail(0);
}

inline void Vorpal::CheckHMAC(std::string hmac, std::string body, std::string appId) {
    std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create(strEnc("HMAC(SHA-256)")));
    mac->set_key(reinterpret_cast<const uint8_t*>(appId.data()), appId.size());
    mac->update(body);

    auto expectedHmac = Botan::hex_encode(mac->final(), false);
    if (!std::equal(hmac.begin(), hmac.end(), expectedHmac.begin(), expectedHmac.end())) {
        this->CloseProgram();
    }
}

void Vorpal::GetApplication(std::string appId) {
    auto cli = SecureInit();

    cli.set_default_headers({
        {strEnc("ValorId"), Utils::base64UrlEncode(appId)},
        {strEnc("ValorKey"), this->GetValorKey()},
        {strEnc("User-Agent"), strEnc("Vorpal API")}, //TODO: some cool system with user-agents that change every 2 minutes.

    });

    auto result = cli.Post(strEnc("/API/checkApplication"), strEnc(""), strEnc("application/x-www-form-urlencoded"));

    if (result) {

        if (!result->has_header(strEnc("Authorization"))) {
            this->CloseProgram();
        }

        auto val = result->get_header_value(strEnc("Authorization"));
        this->CheckHMAC(val, result->body, appId);

        LOG(strEnc("GetApplication Body: %s\n"), result->body.c_str());

        json data = json::parse(result->body);
        if (data[strEnc("Result")]) {
            this->AppInfo.Error = strEnc("");
            this->AppInfo.Name = data[strEnc("Name")];
            this->AppInfo.Domain = data[strEnc("Domain")];
            this->AppInfo.Version = data[strEnc("Version")];
            this->AppInfo.Login = data[strEnc("Login")];
            this->AppInfo.Key = data[strEnc("Key")];
            this->AppInfo.HWID = data[strEnc("HWID")].get<bool>();  //"HWID":"true" they can't do it
            this->AppInfo.Maintenance = data[strEnc("Maintenance")].get<bool>();
            this->AppInfo.Developer = data[strEnc("Developer")].get<bool>();
            this->AppInfo.AntiDebug = data[strEnc("AntiDebug")].get<bool>();
            this->AppInfo.AntiVM = data[strEnc("AntiVM")].get<bool>();
            this->AppInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->AppInfo.Result = data[strEnc("Result")].get<bool>();
        }
        else {
            this->AppInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->AppInfo.Result = data[strEnc("Result")].get<bool>();
            this->AppInfo.Error = data[strEnc("Error")];
        }
    }
}

void Vorpal::registr(std::string username, std::string password, std::string email) {
    auto cli = SecureInit();

    cli.set_default_headers({
        {strEnc("ValorId"), Utils::base64UrlEncode(this->brandId)},
        {strEnc("ValorKey"), this->GetValorKey()},
        {strEnc("User-Agent"), strEnc("Vorpal API")} //TODO: some cool system with user-agents that change every 2 minutes.
    });

    httplib::Params params{
        { strEnc("username"), Utils::base64UrlEncode(username).c_str() },
        { strEnc("email"), Utils::base64UrlEncode(email).c_str() },
        { strEnc("password"), Utils::base64UrlEncode(password).c_str() },
    };

    auto result = cli.Post(strEnc("/API/register"), params);

    if (result) {
        if (!result->has_header(strEnc("Authorization"))) {
            this->CloseProgram();
        }

        auto val = result->get_header_value(strEnc("Authorization"));
        this->CheckHMAC(val, result->body, this->brandId);

        LOG(strEnc("Register Body: %s\n"), result->body.c_str());

        json data = json::parse(result->body);
        if (data[strEnc("Result")]) {
            this->LoginAppInfo.Error = strEnc("");
            this->LoginAppInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->LoginAppInfo.Result = data[strEnc("Result")].get<bool>();
        }
        else {
            this->LoginAppInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->LoginAppInfo.Result = data[strEnc("Result")].get<bool>();
            this->LoginAppInfo.Error = data[strEnc("Error")];
        }
    }
}

void Vorpal::redeemLicense(std::string licenseKey) {
    auto cli = SecureInit();

    cli.set_default_headers({
        {strEnc("ValorId"), Utils::base64UrlEncode(this->brandId)},
        {strEnc("ValorKey"), this->GetValorKey()},
        {strEnc("User-Agent"), strEnc("Vorpal API")} //TODO: some cool system with user-agents that change every 2 minutes.
    });
    httplib::Params params{
        {strEnc("username"), Utils::base64UrlEncode(username).c_str()},
        {strEnc("licensekey"), Utils::base64UrlEncode(licenseKey).c_str()}
    };

    auto result = cli.Post(strEnc("/API/redeemLicense"), params);

    if (result) {
        if (!result->has_header(strEnc("Authorization"))) {
            this->CloseProgram();
        }

        auto val = result->get_header_value(strEnc("Authorization"));
        this->CheckHMAC(val, result->body, this->brandId);

        LOG(strEnc("redeemLicense Body: %s\n"), result->body.c_str());

        json data = json::parse(result->body);
        if (data[strEnc("Result")]) {
            this->LoginAppInfo.Error = strEnc("");
            this->LoginAppInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->LoginAppInfo.Result = data[strEnc("Result")].get<bool>();
        }
        else {
            this->LoginAppInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->LoginAppInfo.Result = data[strEnc("Result")].get<bool>();
            this->LoginAppInfo.Error = data[strEnc("Error")];
        }
    }
}

void Vorpal::loginApplication(std::string appId) {
    auto cli = SecureInit();

    cli.set_default_headers({
        {strEnc("ValorId"), Utils::base64UrlEncode(appId)},
        {strEnc("ValorKey"), this->GetValorKey()},
        {strEnc("User-Agent"), strEnc("Vorpal API")} //TODO: some cool system with user-agents that change every 2 minutes.
    });

    httplib::Params params{
        { strEnc("username"), Utils::base64UrlEncode(username).c_str()},
        { strEnc("password"), Utils::base64UrlEncode(password).c_str() },
        { strEnc("hwid"), Utils::base64UrlEncode(VorpalAPI::HWID::grabHWID()).c_str()},
        { strEnc("userId"), Utils::base64UrlEncode(this->LoginInfo.HashedID).c_str()}
    };

    auto result = cli.Post(strEnc("/API/loginApplication"), params);

    if (result) {
        if (!result->has_header(strEnc("Authorization"))) {
            this->CloseProgram();
        }

        auto val = result->get_header_value(strEnc("Authorization"));
        this->CheckHMAC(val, result->body, appId);

        LOG(strEnc("loginApplication Body: %s\n"), result->body.c_str());

        json data = json::parse(result->body);
        if (data[strEnc("Result")]) {

            if (!result->has_header(strEnc("Session"))) {
                this->CloseProgram();
            }

            // Get the "Set-Cookie" header from the response
            this->sessionId = result->get_header_value(strEnc("Session"));

            this->LoginAppInfo.Error = strEnc("");
            this->LoginAppInfo.HashedID = data[strEnc("HashedID")];
            this->LoginAppInfo.Username = data[strEnc("Username")];
            this->LoginAppInfo.Email = data[strEnc("Email")];
            this->LoginAppInfo.Status = data[strEnc("Status")];
            this->LoginAppInfo.Rank = data[strEnc("Rank")];
            this->LoginAppInfo.Key = data[strEnc("Key")];
            this->LoginAppInfo.HWID = data[strEnc("HWID")];
            this->LoginAppInfo.Expiry = data[strEnc("Expiry")].get<uint64_t>();
            this->LoginAppInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->LoginAppInfo.Result = data[strEnc("Result")].get<bool>();
        }
        else {
            this->LoginAppInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->LoginAppInfo.Result = data[strEnc("Result")].get<bool>();
            this->LoginAppInfo.Error = data[strEnc("Error")];
        }
    }
}

void Vorpal::login(std::string username, std::string password) {
    auto cli = SecureInit();

    this->username = username;
    this->password = password;

    cli.set_default_headers({
        {strEnc("ValorId"), Utils::base64UrlEncode(this->brandId)},
        {strEnc("ValorKey"), this->GetValorKey()},
        {strEnc("User-Agent"), strEnc("Vorpal API")} //TODO: some cool system with user-agents that change every 2 minutes.
    });

    httplib::Params params{
        { strEnc("username"), Utils::base64UrlEncode(username).c_str()},
        { strEnc("password"), Utils::base64UrlEncode(password).c_str() },
        { strEnc("hwid"), Utils::base64UrlEncode(VorpalAPI::HWID::grabHWID()).c_str()}
    };
    
    auto result = cli.Post(strEnc("/API/login"), params);

    if (result) {
        if (!result->has_header(strEnc("Authorization"))) {
            this->CloseProgram();
        }

        auto val = result->get_header_value(strEnc("Authorization"));
        this->CheckHMAC(val, result->body, this->brandId);

        LOG(strEnc("login Body: %s\n"), result->body.c_str());

        json data = json::parse(result->body);
        if (data[strEnc("Result")]) {
            this->LoginInfo.Error = strEnc("");
            this->LoginInfo.HashedID = data[strEnc("HashedID")];
            this->LoginInfo.Username = data[strEnc("Username")];
            this->LoginInfo.Email = data[strEnc("Email")];
            this->LoginInfo.Status = data[strEnc("Status")];
            this->LoginInfo.Rank = data[strEnc("Rank")];
            //this->LoginInfo.Key = data[strEnc("KeyInfo")];
            this->LoginInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->LoginInfo.Result = data[strEnc("Result")].get<bool>();
            if (!data[strEnc("KeyInfo")].is_null()) {
                //Credits: ChatGPT
                json key_info = data[strEnc("KeyInfo")];
                this->LoginInfo.Key.clear();
                // Loop over the key-value pairs of the "KeyInfo" object
                for (auto& key_info_kv : key_info.items()) {
                    std::string key = key_info_kv.key(); // Get the key
                    json value = key_info_kv.value(); // Get the value

                    // Loop over the array in the value object
                    for (json::iterator it = value.begin(); it != value.end(); ++it) {
                        json key_info_obj = *it;

                        LicenseKey keyInfoTmp;
                        keyInfoTmp.AppId = key;
                        keyInfoTmp.ApplicationName = key_info_obj[strEnc("ApplicationName")];
                        keyInfoTmp.License = key_info_obj[strEnc("licenseKey")];

                        if (key_info_obj[strEnc("expiryDays")].is_number()) {
                            keyInfoTmp.ExpiryDays = std::to_string(key_info_obj[strEnc("expiryDays")].get<int>());
                        }
                        else {
                            keyInfoTmp.ExpiryDays = key_info_obj[strEnc("expiryDays")];
                        }

                        keyInfoTmp.ExpiryDate = key_info_obj[strEnc("expiryDate")].get<uint64_t>();

                        if (key_info_obj[strEnc("hwid")].is_number()) {
                            keyInfoTmp.HWID = std::to_string(key_info_obj[strEnc("hwid")].get<uint64_t>());
                        }
                        else {
                            keyInfoTmp.HWID = key_info_obj[strEnc("hwid")];
                        }

                        keyInfoTmp.status = key_info_obj[strEnc("status")];
                        this->LoginInfo.Key.push_back(keyInfoTmp);
                        //keyInfoTm = key_info_obj[strEnc("lastHWIDReset")]; //not supported rn dont see what we need it for rn
                    }
                }
            }
        }
        else {
            this->LoginInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->LoginInfo.Result = data[strEnc("Result")].get<bool>();
            this->LoginInfo.Error = data[strEnc("Error")];
        }
    }
}

void Vorpal::heartbeat(std::string HashedId, std::string appId) {
    auto cli = SecureInit();

    cli.set_default_headers({
        {strEnc("ValorId"), Utils::base64UrlEncode(appId)},
        {strEnc("ValorKey"), this->GetValorKey()},
        {strEnc("User-Agent"), strEnc("Vorpal API")}, //TODO: some cool system with user-agents that change every 2 minutes.
        {strEnc("Session"), this->sessionId}
    });

    httplib::Params params{
        { strEnc("userId"), Utils::base64UrlEncode(HashedId).c_str() },
        { strEnc("hwid"), Utils::base64UrlEncode(VorpalAPI::HWID::grabHWID()).c_str() }
    };

    auto result = cli.Post(strEnc("/API/heartbeat"), params);

    if (result) {

        if (!result->has_header(strEnc("Authorization"))) {
            this->CloseProgram();
        }

        auto val = result->get_header_value(strEnc("Authorization"));
        this->CheckHMAC(val, result->body, appId);

        LOG(strEnc("heartbeat Body: %s\n"), result->body.c_str());

        json data = json::parse(result->body);
        if (data[strEnc("Result")]) {
            this->HeartbeatInfo.Error = strEnc("");
            this->HeartbeatInfo.HashedID = data[strEnc("HashedID")];
            this->HeartbeatInfo.Username = data[strEnc("Username")];
            this->HeartbeatInfo.HWID = data[strEnc("HWID")];
            this->HeartbeatInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->HeartbeatInfo.Result = data[strEnc("Result")].get<bool>();
        }
        else {
            this->HeartbeatInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->HeartbeatInfo.Result = data[strEnc("Result")].get<bool>();
            this->HeartbeatInfo.Error = data[strEnc("Error")];
        }
    }
}

std::string Vorpal::GetFile(std::string key, std::string appId) {
    auto cli = SecureInit();

    cli.set_default_headers({
        {strEnc("ValorId"), Utils::base64UrlEncode(appId)},
        {strEnc("ValorKey"), this->GetValorKey()},
        {strEnc("User-Agent"), strEnc("Vorpal API")}, //TODO: some cool system with user-agents that change every 2 minutes.
        {strEnc("Session"), this->sessionId}
    });
    httplib::Params params{
        { strEnc("VariableKey"), Utils::base64UrlEncode(key) }
    };
    auto result = cli.Post(strEnc("/API/variablefile"), params);

    if (result) {

        if (!result->has_header(strEnc("Authorization"))) {
            this->CloseProgram();
        }

        auto val = result->get_header_value(strEnc("Authorization"));
        //For some reason {\"embeds\":[\"0\"} gets added randomly on file api sometimes, with no reason. making it fail the checkHmac.
        this->CheckHMAC(val, result->body, appId);

        LOG(strEnc("GetFile Body: %s\n"), result->body.c_str());

        json data = json::parse(result->body);

        if (data[strEnc("Result")]) {
            return data[key.c_str()];

        }
        else {
            //    this->VarInfo.Time = data[strEnc("Time")].get<uint64_t>();
            //    this->VarInfo.Result = data[strEnc("Result")].get<bool>());
            //    this->VarInfo.Error = data[strEnc("Error")];
        }
    }
    return "";
}

void Vorpal::GetBrandVariables() {
    auto cli = SecureInit();

    cli.set_default_headers({
        {strEnc("ValorId"), Utils::base64UrlEncode(this->brandId)},
        {strEnc("ValorKey"), this->GetValorKey()},
        {strEnc("User-Agent"), strEnc("Vorpal API")}, //TODO: some cool system with user-agents that change every 2 minutes.
        {strEnc("Session"), this->sessionId}
        });

    auto result = cli.Post(strEnc("/API/brandvariables"), strEnc(""), strEnc("application/x-www-form-urlencoded"));

    if (result) {
        if (!result->has_header(strEnc("Authorization"))) {
            this->CloseProgram();
        }

        auto val = result->get_header_value(strEnc("Authorization"));
        this->CheckHMAC(val, result->body, this->brandId);

        LOG(strEnc("GetBrandVariable Body: %s\n"), result->body.c_str());

        json data = json::parse(result->body);

        if (data[strEnc("Result")]) {
            
        }
        else {

        }
    }
}


void Vorpal::GetBrandVariable(std::string key) {
    auto cli = SecureInit();

    cli.set_default_headers({
        {strEnc("ValorId"), Utils::base64UrlEncode(this->brandId)},
        {strEnc("ValorKey"), this->GetValorKey()},
        {strEnc("User-Agent"), strEnc("Vorpal API")}, //TODO: some cool system with user-agents that change every 2 minutes.
        });

    httplib::Params params{
        { strEnc("VariableKey"), Utils::base64UrlEncode(key) }
    };

    auto result = cli.Post(strEnc("/API/brandvariable"), params);

    if (result) {
        if (!result->has_header(strEnc("Authorization"))) {
            this->CloseProgram();
        }

        auto val = result->get_header_value(strEnc("Authorization"));
        this->CheckHMAC(val, result->body, this->brandId);

        LOG(strEnc("GetBrandVariable Body: %s\n"), result->body.c_str());

        json data = json::parse(result->body);

        if (data[strEnc("Result")]) {
            //this->currentVar = (std::string)data[key.c_str()];
            this->currentVar = (std::string)data[key.c_str()];
            this->VarInfo.Error = strEnc("");
            this->VarInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->VarInfo.Result = data[strEnc("Result")].get<bool>();
        }
        else {
            this->VarInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->VarInfo.Result = data[strEnc("Result")].get<bool>();
            this->VarInfo.Error = data[strEnc("Error")];
        }
    }
}


void Vorpal::GetVariable(std::string key, std::string appId) {
    auto cli = SecureInit();

    cli.set_default_headers({
        {strEnc("ValorId"), Utils::base64UrlEncode(appId)},
        {strEnc("ValorKey"), this->GetValorKey()},
        {strEnc("User-Agent"), strEnc("Vorpal API")}, //TODO: some cool system with user-agents that change every 2 minutes.
        {strEnc("Session"), this->sessionId}
    });

    httplib::Params params{
        { strEnc("VariableKey"), Utils::base64UrlEncode(key) }
    };

    auto result = cli.Post(strEnc("/API/variable"), params);

    if (result) {
        if (!result->has_header(strEnc("Authorization"))) {
            this->CloseProgram();
        }

        auto val = result->get_header_value(strEnc("Authorization"));
        this->CheckHMAC(val, result->body, appId);

        LOG(strEnc("GetVariable Body: %s\n"), result->body.c_str());

        json data = json::parse(result->body);

        if (data[strEnc("Result")]) {
            //this->currentVar = (std::string)data[key.c_str()];
            this->currentVar = (std::string)data[key.c_str()];
            this->VarInfo.Error = strEnc("");
            this->VarInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->VarInfo.Result = data[strEnc("Result")].get<bool>();
        }
        else {
            this->VarInfo.Time = data[strEnc("Time")].get<uint64_t>();
            this->VarInfo.Result = data[strEnc("Result")].get<bool>();
            this->VarInfo.Error = data[strEnc("Error")];
        }
    }
}
