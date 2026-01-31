#pragma once
#include "ulti/support.h"

// ===== Forward =====
struct FileInfo;
struct EventInfo;

class EtwController
{
public:
    // Singleton (pointer)
    static EtwController* GetInstance();

    // Service lifecycle entrypoints
    static void StartThunk();
    static void StopThunk();

#ifdef _DEBUG
    void RunDebugBlocking();
#endif

private:
    EtwController();
    ~EtwController();

    EtwController(const EtwController&) = delete;
    EtwController& operator=(const EtwController&) = delete;

private:
    // ===== Main lifecycle =====
    void Start();
    void Stop();

    // ================= Logger =================
    void PushLog(const std::wstring& s);
    void LoggerThreadProc();
    void StartLoggerThread();

    std::queue<std::wstring> m_logQueue;
    std::mutex m_logMutex;
    std::jthread m_loggerThread;
    bool m_stopLogger = false;

    // ================= ETW =================
    void StartProviderBlocking();

    krabs::user_trace m_trace;
    std::jthread m_traceThread;

    ULONG m_curPid;

    // ================= Process tracking =================
    std::mutex m_lockProc;

    // ================= Identity tables =================
    // name_hash -> printed (IH)
    std::unordered_set<ULONGLONG> m_printedNameHash;

    // file_object -> name_hash
    std::unordered_map<ULONGLONG, ULONGLONG> m_objToNameHash;

    // printed file_object (IO)
    std::unordered_set<ULONGLONG> m_printedObj;

    // printed file_key (IK)
    std::unordered_set<ULONGLONG> m_printedKey;

    std::mutex m_identityMutex;

    // ================= Process logging =================
    void MaybePrintProcessInfo(ULONG eid, ULONGLONG ts, ULONG pid, const std::wstring& path);

    // ================= Identity logging =================
    void MaybePrintIH(ULONGLONG ts, const std::wstring& path, ULONGLONG& out_name_hash);
    void MaybePrintIO(ULONGLONG ts, ULONGLONG file_object, ULONGLONG name_hash);
    void MaybePrintIK(ULONG eid, ULONGLONG ts, ULONGLONG file_key, ULONGLONG name_hash);

    // ================= File operation logging =================
    void LogFileCreateOperation(ULONG eid, ULONGLONG ts, ULONGLONG name_hash);
    void LogFileWriteOperation(ULONG eid, ULONGLONG ts, ULONGLONG file_object, ULONGLONG size);
    void LogFileRenameOperation(ULONG eid, ULONGLONG ts, ULONGLONG name_hash, ULONGLONG file_object, ULONGLONG file_key);
    void LogFileDeleteOperation(ULONG eid, ULONGLONG ts, ULONGLONG name_hash, ULONGLONG file_object, ULONGLONG file_key);

    // ================= File handlers =================
    void HandleFileCreate(ULONG pid, ULONG eid, ULONGLONG ts, krabs::parser& parser);
    void HandleFileCleanup(ULONG eid, ULONGLONG ts, krabs::parser& parser);
    void HandleFileWrite(ULONG pid, ULONG eid, ULONGLONG ts, krabs::parser& parser);
    void HandleFileRename(ULONG pid, ULONG eid, ULONGLONG ts, krabs::parser& parser);
    void HandleFileDelete(ULONG pid, ULONG eid, ULONGLONG ts, krabs::parser& parser);

    // ===== Debug =====
    static void PrintAllProp(krabs::schema schema, krabs::parser& parser);
};

struct FileInfo
{
    std::wstring path;
    ULONGLONG name_hash = 0;
    bool written = false;
    bool printed = false;
};

struct EventInfo
{
    ULONG prov = 0;
    ULONG eid = 0;
    ULONG pid = 0;
    std::wstring path;
    ULONGLONG name_hash = 0;
    ULONGLONG file_object = 0;
    ULONGLONG file_key = 0;
};

// ===== Event IDs =====
#define KFE_NAME_CREATE                10
#define KFE_NAME_DELETE                11
#define KFE_CREATE                     12
#define KFE_CLEANUP                    13
#define KFE_CLOSE                      14
#define KFE_READ                       15
#define KFE_WRITE                      16
#define KFE_SET_INFORMATION            17
#define KFE_SET_DELETE                 18
#define KFE_RENAME                     19
#define KFE_DIR_ENUM                   20
#define KFE_FLUSH                      21
#define KFE_QUERY_INFORMATION          22
#define KFE_FSCTL                      23
#define KFE_OPERATION_END              24
#define KFE_DIR_NOTIFY                 25
#define KFE_DELETE_PATH                26
#define KFE_RENAME_PATH                27
#define KFE_SET_LINK_PATH              28
#define KFE_RENAME_29                  29
#define KFE_CREATE_NEW_FILE            30
#define KFE_SET_SECURITY               31
#define KFE_QUERY_SECURITY             32
#define KFE_SET_EA                     33
#define KFE_QUERY_EA                   34
