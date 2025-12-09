#pragma once
#define _CRT_SECURE_NO_DEPRECATE
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#ifndef ULTI_SUPPORT_H_
#define ULTI_SUPPORT_H_
#include "include.h"

namespace ulti
{
    std::wstring StrToWstr(const std::string& str);
    std::string WstrToStr(const std::wstring& wstr);
    std::string CharVectorToString(const std::vector<char>& v);
    std::vector<char> StringToVectorChar(const std::string& s);
    std::vector<unsigned char> StringToVectorUChar(const std::string& s);
    std::wstring ToLower(const std::wstring& wstr);
    std::string ToLower(const std::string& wstr);
    void ToLowerOverride(std::string& wstr);
    void ToLowerOverride(std::wstring& wstr);

    template <typename T>
    void AddVectorsInPlace(std::vector<T>& dest, const std::vector<T>& source) {
        dest.insert(dest.end(), source.begin(), source.end());
    }

    std::vector<std::string> SplitString(const std::string& input,
        const std::string& delimiter);

    ull GetCurrentSteadyTimeInSec();

    bool IsCurrentX86Process();

    bool CreateDir(const std::wstring& dir_path);

    bool KillProcess(DWORD pid);

    bool IsRunningAsSystem();

    std::wstring GetProcessPath(DWORD pid);

    /**
    * @brief Get the total CPU usage percentage of the current thread
    *        since it started execution.
    *
    * This function uses GetThreadTimes() to calculate the ratio between
    * total thread CPU time (user + kernel) and the wall-clock time since
    * the thread started.
    *
    * @return double - CPU usage percentage in range [0, 100].
    */
    double GetThreadTotalCpuUsage();

    /**
     * @brief Sleep the thread adaptively to maintain target CPU usage.
     *
     * This function measures thread CPU time (user+kernel) and compares
     * it against wall time. If current CPU usage exceeds cpu_perc, the
     * thread will sleep for a calculated duration to lower the usage.
     *
     * @param cpu_perc Target CPU percentage (e.g., 5.0 for 5%)
     */
    void ThreadPerfCtrlSleep(double cpu_perc = 5.0);

}

#endif // ULTI_SUPPORT_H_
