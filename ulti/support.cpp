#include "support.h"
#include "debug.h"

namespace ulti
{
    std::wstring StrToWstr(const std::string& str) {
        if (str.empty()) return L"";

        int size_needed = MultiByteToWideChar(CP_UTF8, 0,
            str.c_str(), static_cast<int>(str.size()),
            nullptr, 0);
        if (size_needed <= 0) {
            return L"";
        }

        std::wstring wstr(size_needed, L'\0');
        MultiByteToWideChar(CP_UTF8, 0,
            str.c_str(), static_cast<int>(str.size()),
            &wstr[0], size_needed);
        return wstr;
    }

    std::string WstrToStr(const std::wstring& wstr) {
        if (wstr.empty()) return "";

        int size_needed = WideCharToMultiByte(CP_UTF8, 0,
            wstr.c_str(), static_cast<int>(wstr.size()),
            nullptr, 0, nullptr, nullptr);
        if (size_needed <= 0) {
            return "";
        }

        std::string str(size_needed, '\0');
        WideCharToMultiByte(CP_UTF8, 0, 
            wstr.c_str(), static_cast<int>(wstr.size()), 
            &str[0], size_needed, nullptr, nullptr);
        return str;
    }

    std::string CharVectorToString(const std::vector<char>& v)
    {
        return std::string(v.begin(), v.end());
    }

    std::vector<char> StringToVectorChar(const std::string& s)
    {
        return std::vector<char>(s.begin(), s.end());
    }

    std::vector<unsigned char> StringToVectorUChar(const std::string& s)
    {
        return std::vector<unsigned char>(s.begin(), s.end());
    }

    std::wstring ToLower(const std::wstring& wstr)
    {
        std::wstring result = wstr;
        CharLowerBuffW(result.data(), result.size());
        return result;
    }

    std::string ToLower(const std::string& wstr)
    {
        std::string result = wstr;
        CharLowerBuffA(result.data(), result.size());
        return result;
    }

    void ToLowerOverride(std::wstring& wstr)
    {
        CharLowerBuffW(wstr.data(), wstr.size());
    }

    void ToLowerOverride(std::string& wstr)
    {
        CharLowerBuffA(wstr.data(), wstr.size());
    }

    // Split a string by a given delimiter into a vector of strings.
    std::vector<std::string> SplitString(const std::string& input,
        const std::string& delimiter) {
        std::vector<std::string> result;
        size_t start = 0;
        size_t end = 0;

        while ((end = input.find(delimiter, start)) != std::string::npos) {
            result.push_back(input.substr(start, end - start));
            start = end + delimiter.length();
        }
        // Add the last token
        result.push_back(input.substr(start));
        return result;
    }

    ull GetCurrentSteadyTimeInSec()
    {
        return (ull)(duration_cast<seconds>(steady_clock::now().time_since_epoch()).count());
    }

    bool IsCurrentX86Process()
    {
        #if defined(__x86_64__) || defined(_M_X64)
            return false;
        #elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
            return true;
        #endif
    }

    bool CreateDir(const std::wstring& dir_path)
    {
        BOOL status = ::CreateDirectory(dir_path.c_str(), NULL);
        if (status == TRUE || GetLastError() == ERROR_ALREADY_EXISTS)
        {
            return true;
        }
        else if (GetLastError() == ERROR_PATH_NOT_FOUND)
        {
            try {
                fs::create_directories(dir_path);
            }
            catch (const fs::filesystem_error&) {
                return false;
            }
            return true;
        }
        else {
            return false;
        }

        return false;
    }
    
    bool KillProcess(DWORD pid)
    {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess == NULL) {
            return false;
        }
        defer{ CloseHandle(hProcess); };
        if (!TerminateProcess(hProcess, 0)) {
            return false;
        }
        return true;
    }

    bool IsRunningAsSystem() {
        HANDLE h_token = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h_token)) {
            return false;
        }

        DWORD size = 0;
        TOKEN_USER* token_user = nullptr;
        GetTokenInformation(h_token, TokenUser, NULL, 0, &size);
        token_user = (TOKEN_USER*)malloc(size);

        if (!token_user || !GetTokenInformation(h_token, TokenUser, token_user, size, &size)) {
            if (h_token) CloseHandle(h_token);
            if (token_user) free(token_user);
            return false;
        }

        SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
        PSID system_sid = NULL;
        if (!AllocateAndInitializeSid(&nt_authority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &system_sid)) {
            if (h_token) CloseHandle(h_token);
            if (token_user) free(token_user);
            return false;
        }

        BOOL is_system = EqualSid(system_sid, token_user->User.Sid);
        FreeSid(system_sid);
        CloseHandle(h_token);
        free(token_user);

        return is_system;
    }

    std::wstring GetProcessPath(DWORD pid) {
        std::wstring path;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess) {
            WCHAR buffer[MAX_PATH];
            DWORD size = MAX_PATH;

            if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size)) {
                path.assign(buffer, size);
            }

            CloseHandle(hProcess);
        }

        return path;
    }

    double GetThreadTotalCpuUsage()
    {
        FILETIME creation_time, exit_time, kernel_time, user_time, now;
        if (!GetThreadTimes(GetCurrentThread(), &creation_time, &exit_time,
            &kernel_time, &user_time))
        {
            return 0.0;
        }

        GetSystemTimeAsFileTime(&now);

        ull t_create = (((ull)creation_time.dwHighDateTime) << 32) | creation_time.dwLowDateTime;
        ull t_now = (((ull)now.dwHighDateTime) << 32) | now.dwLowDateTime;
        ull t_kernel = (((ull)kernel_time.dwHighDateTime) << 32) | kernel_time.dwLowDateTime;
        ull t_user = (((ull)user_time.dwHighDateTime) << 32) | user_time.dwLowDateTime;

        ull wall_time = t_now - t_create;
        ull cpu_time = t_kernel + t_user;

        if (wall_time == 0)
            return 0.0;

        double usage = ((double)cpu_time / (double)wall_time) * 100.0;
        if (usage > 100.0)
            usage = 100.0;
        return usage;
    }

    void ThreadPerfCtrlSleep(double cpu_perc)
    {
        if (cpu_perc <= 0.0)
        {
            Sleep(100);
            return;
        }

        // Static variables to keep historical data for up to 1 hour
        static ull s_start_time_100ns = 0;   // System start time for this 1h window
        static ull s_base_cpu_100ns = 0;     // CPU time at start of window
        static bool s_initialized = false;

        FILETIME creation_time, exit_time, kernel_time, user_time;
        if (!GetThreadTimes(GetCurrentThread(), &creation_time, &exit_time,
            &kernel_time, &user_time))
        {
            return;
        }

        auto t_now = std::chrono::duration_cast<std::chrono::duration<ull, std::ratio<1, 10'000'000>>>(std::chrono::steady_clock::now().time_since_epoch()).count();

        // Convert FILETIME to 64-bit integers (100 ns units)
        auto t_kernel = (((ull)kernel_time.dwHighDateTime) << 32) | kernel_time.dwLowDateTime;
        auto t_user = (((ull)user_time.dwHighDateTime) << 32) | user_time.dwLowDateTime;

        auto cpu_time = t_kernel + t_user;

        // Initialize base values for 1-hour tracking
        if (!s_initialized)
        {
            s_start_time_100ns = t_now;
            s_base_cpu_100ns = cpu_time;
            s_initialized = true;
            return;
        }
        auto wall_time = t_now - s_start_time_100ns;

        if (wall_time == 0 || cpu_time == 0)
            return;

        // Check if more than 1 hour has passed (1 hour = 3600s = 36,000,000,000 * 100ns)
        const ull ONE_HOUR_100NS = 3600ULL * 10000000ULL;
        if (wall_time >= ONE_HOUR_100NS)
        {
            // Reset stats for new 1-hour window
            s_start_time_100ns = t_now;
            s_base_cpu_100ns = cpu_time;
            return;
        }

        // Compute deltas relative to base values
        ull rel_cpu = cpu_time - s_base_cpu_100ns;
        if (rel_cpu == 0)
            return;

        // Compute sleep time based on desired CPU usage
        ull sleep_100ns = cpu_time * 100 / ((ull)(cpu_perc * 1000) / 1000) - wall_time;
        ull sleep_ms = (ull)sleep_100ns / 10000;
        if (sleep_ms >= 1.0 && sleep_ms <= 3600000ULL)
        {
            PrintDebugW("Sleep %d ms", sleep_ms);
            Sleep((DWORD)sleep_ms);
        }
    }

}
