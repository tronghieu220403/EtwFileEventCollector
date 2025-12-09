#pragma once

#ifndef ULTI_DEBUG_H_
#define ULTI_DEBUG_H_

#include "include.h"

#define DEBUG_LOG_THRESHOLD 1000
#define LOG_PATH L"E:\\hieunt210330\\hieunt210330\\log.txt"

namespace debug {

    // Initializes the debug log file.
    void InitDebugLog();

    // Cleans up the debug log file.
    void CleanupDebugLog();

    // Writes a debug message to the log file.
    void WriteDebugToFileW(const std::wstring& s);

    // Logs a formatted debug message.
    void DebugPrintW(const wchar_t* pwsz_format, ...);

    // Retrieves a formatted error message from a Windows error code.
    std::wstring GetErrorMessage(DWORD errorCode);

}  // namespace debug 

#define PrintDebugW(str, ...) \
    debug::DebugPrintW(L"[%ws:%d] " str L"\n", __FUNCTIONW__, __LINE__, __VA_ARGS__)

#endif // ULTI_DEBUG_H_