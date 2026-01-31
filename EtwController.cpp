#include "EtwController.h"

#include <sstream>
#include <fstream>
#include <iostream>

using namespace std;

namespace helper {
    ull GetWstrHash(const std::wstring& ws)
    {
        const ull FNV_OFFSET = 1469598103934665603ULL;
        const ull FNV_PRIME = 1099511628211ULL;

        ull hash = FNV_OFFSET;
        for (wchar_t c : ws)
        {
            hash ^= static_cast<ull>(c);
            hash *= FNV_PRIME;
        }
        return hash;
    }
}

// ================= Singleton =================
EtwController* EtwController::GetInstance()
{
    static EtwController inst;
    return &inst;
}

void EtwController::StartThunk()
{
    GetInstance()->Start();
}

void EtwController::StopThunk()
{
    GetInstance()->Stop();
}

// ================= Ctor / Dtor =================
EtwController::EtwController()
    : m_trace(L"hieunt"),
    m_curPid(GetCurrentProcessId())
{
}

EtwController::~EtwController()
{
    Stop();
}

// ================= Debug =================
void EtwController::PrintAllProp(krabs::schema schema, krabs::parser& parser)
{
    std::wstringstream ss;
    ss << L"task_name=" << schema.task_name() << L", ";
    ss << L"PID=" << schema.process_id() << L", ";

    for (const auto& x : parser.properties())
    {
        std::wstring wstr;
        try { wstr = parser.parse<std::wstring>(x.name()); }
        catch (...) {
            try { wstr = to_wstring(parser.parse<UINT64>(x.name())); }
            catch (...) {
                try { wstr = to_wstring(parser.parse<UINT32>(x.name())); }
                catch (...) {
                    try { wstr = to_wstring(parser.parse<UINT16>(x.name())); }
                    catch (...) {
                        try { wstr = to_wstring(parser.parse<UINT8>(x.name())); }
                        catch (...) {}
                    }
                }
            }
        }

        if (!wstr.empty())
            ss << x.name() << L" " << wstr << L", ";
    }

    //if (ss.str().find(L"load\\test") != std::wstring::npos)
    //    std::wcout << ss.str() << endl;
}

// ================= Logger =================
void EtwController::PushLog(const std::wstring& s)
{
    if (m_stopLogger == true) {
        return;
    }
    std::lock_guard<std::mutex> l(m_logMutex);
    m_logQueue.push(s);
}

void EtwController::LoggerThreadProc()
{
    while (true)
    {
        Sleep(5000);

        if (m_stopLogger) break;

        std::queue<std::wstring> local;

        {
            std::lock_guard<std::mutex> l(m_logMutex);
            if (m_logQueue.empty())
                continue;

            if (m_logQueue.size() >= 10000)
                m_logQueue = std::queue<std::wstring>();

            local.swap(m_logQueue);
        }

        std::wofstream ofs(L"C:\\hieunt_log.jsonl", std::ios::app);
        if (!ofs.is_open())
            continue;

        while (!local.empty())
        {
            ofs << local.front() << L"\n";
            local.pop();
        }
    }
}

void EtwController::StartLoggerThread()
{
    m_loggerThread = std::jthread([this]() {
        LoggerThreadProc();
        });
}

// ================= Process logging =================
void EtwController::MaybePrintProcessInfo(ULONG eid, ULONGLONG ts, ULONG pid, const std::wstring& path)
{
    if (path.empty())
        return;

    std::wstringstream ss;
    ss << L"P,I," << eid << L"," << ts << L"," << pid << L"," << path;
    PushLog(ss.str());
}

// ================= Identity logging =================
void EtwController::MaybePrintIH(ULONGLONG ts, const std::wstring& path, ULONGLONG& out_name_hash)
{
    out_name_hash = 0;
    if (path.empty())
        return;

    std::wstring lower = ulti::ToLower(path);
    ULONGLONG name_hash = helper::GetWstrHash(lower);
    out_name_hash = name_hash;

    std::lock_guard<std::mutex> lock(m_identityMutex);
    if (!m_printedNameHash.insert(name_hash).second)
        return;

    std::wstringstream ss;
    ss << L"F,IH,0," << ts << L"," << name_hash << L"," << path;
    PushLog(ss.str());

    if (m_printedNameHash.size() >= 100000)
        m_printedNameHash.clear();
}

void EtwController::MaybePrintIO(ULONGLONG ts, ULONGLONG file_object, ULONGLONG name_hash)
{
    if (file_object == 0 || name_hash == 0)
        return;

    std::lock_guard<std::mutex> lock(m_identityMutex);
    if (!m_printedObj.insert(file_object).second)
        return;

    std::wstringstream ss;
    ss << L"F,IO,0," << ts << L"," << file_object << L"," << name_hash;
    PushLog(ss.str());

    if (m_printedObj.size() >= 100000)
        m_printedObj.clear();
}

void EtwController::MaybePrintIK(ULONG eid, ULONGLONG ts, ULONGLONG file_key, ULONGLONG name_hash)
{
    if (file_key == 0 || name_hash == 0)
        return;

    std::lock_guard<std::mutex> lock(m_identityMutex);
    if (!m_printedKey.insert(file_key).second)
        return;

    std::wstringstream ss;
    ss << L"F,IK," << eid << L"," << ts << L"," << file_key << L"," << name_hash;
    PushLog(ss.str());

    if (m_printedKey.size() >= 100000)
        m_printedKey.clear();
}

// ================= File operation logging =================
void EtwController::LogFileCreateOperation(ULONG eid, ULONGLONG ts, ULONGLONG name_hash)
{
    std::wstringstream ss;
    ss << L"F,C," << eid << L"," << ts << L"," << name_hash;
    PushLog(ss.str());
}

void EtwController::LogFileWriteOperation(ULONG eid, ULONGLONG ts, ULONGLONG file_object, ULONGLONG size)
{
    std::wstringstream ss;
    ss << L"F,W," << eid << L"," << ts << L"," << file_object << L"," << size;
    PushLog(ss.str());
}

void EtwController::LogFileRenameOperation(ULONG eid, ULONGLONG ts, ULONGLONG name_hash, ULONGLONG file_object, ULONGLONG file_key)
{
    std::wstringstream ss;
    ss << L"F,RN," << eid << L"," << ts << L"," << name_hash << L"," << file_object << L"," << file_key;
    PushLog(ss.str());
}

void EtwController::LogFileDeleteOperation(ULONG eid, ULONGLONG ts, ULONGLONG name_hash, ULONGLONG file_object, ULONGLONG file_key)
{
    std::wstringstream ss;
    ss << L"F,D," << eid << L"," << ts << L"," << name_hash << L"," << file_object << L"," << file_key;
    PushLog(ss.str());
}

// ================= File handlers =================
void EtwController::HandleFileCreate(ULONG pid, ULONG eid, ULONGLONG ts, krabs::parser& parser)
{
    ULONGLONG fo = (ULONGLONG)parser.parse<PVOID>(L"FileObject");
    std::wstring path = parser.parse<std::wstring>(L"FileName");
    UINT32 co = parser.parse<UINT32>(L"CreateOptions");

    // Parse done -> identity decisions first
    ULONGLONG name_hash = 0;
    MaybePrintIH(ts, path, name_hash);
    MaybePrintIO(ts, fo, name_hash);

    // Manage object table for later lookups
    {
        std::lock_guard<std::mutex> lock(m_identityMutex);
        m_objToNameHash[fo] = name_hash;
    }

    // Operation
    if (eid == KFE_CREATE_NEW_FILE)
    {
        LogFileCreateOperation(eid, ts, name_hash);
    }

    // Delete-on-close mapped to delete operation without file key
    if ((co & 0x00001000) != 0)
    {
        LogFileDeleteOperation(eid, ts, name_hash, fo, 0);
    }
}

void EtwController::HandleFileCleanup(ULONG eid, ULONGLONG ts, krabs::parser& parser)
{
    ULONGLONG fo = (ULONGLONG)parser.parse<PVOID>(L"FileObject");
    {
        std::lock_guard<std::mutex> lock(m_identityMutex);
        m_objToNameHash.erase(fo);
    }
}

void EtwController::HandleFileWrite(ULONG pid, ULONG eid, ULONGLONG ts, krabs::parser& parser)
{
    ULONGLONG fo = (ULONGLONG)parser.parse<PVOID>(L"FileObject");

    // Optional size field, keep 0 if missing
    ULONGLONG sz = 0;
    parser.try_parse<ULONGLONG>(L"IoSize", sz);

    // Parse done -> identity decisions first (IO requires name_hash, resolve via obj table)
    ULONGLONG name_hash = 0;
    {
        std::lock_guard<std::mutex> lock(m_identityMutex);
        auto it = m_objToNameHash.find(fo);
        if (it != m_objToNameHash.end())
            name_hash = it->second;
    }
    MaybePrintIO(ts, fo, name_hash);

    // Operation
    LogFileWriteOperation(eid, ts, fo, sz);
}

void EtwController::HandleFileRename(ULONG pid, ULONG eid, ULONGLONG ts, krabs::parser& parser)
{
    ULONGLONG fo = 0;
    ULONGLONG key = 0;
    std::wstring path;
    ULONGLONG name_hash = 0;

    if (eid == KFE_RENAME_PATH)
    {
        parser.try_parse<std::wstring>(L"FileName", path);
        MaybePrintIH(ts, path, name_hash);
    }
    else
    {
        fo = (ULONGLONG)parser.parse<PVOID>(L"FileObject");
        {
            std::lock_guard<std::mutex> lock(m_identityMutex);
            auto it = m_objToNameHash.find(fo);
            if (it != m_objToNameHash.end())
                name_hash = it->second;
        }
    }

    parser.try_parse<ULONGLONG>(L"FileKey", key);

    // Parse done -> identity decisions first
    if (fo != 0)
        MaybePrintIO(ts, fo, name_hash);

    // Operation
    LogFileRenameOperation(eid, ts, name_hash, fo, key);
}

void EtwController::HandleFileDelete(ULONG pid, ULONG eid, ULONGLONG ts, krabs::parser& parser)
{
    if (eid == KFE_NAME_DELETE)
    {
        ULONGLONG key = 0;
        std::wstring path;

        parser.try_parse<ULONGLONG>(L"FileKey", key);
        parser.try_parse<std::wstring>(L"FileName", path);

        ULONGLONG name_hash = 0;
        MaybePrintIH(ts, path, name_hash);
        MaybePrintIK(eid, ts, key, name_hash);
        return;
    }

    ULONGLONG fo = 0;
    ULONGLONG key = 0;
    std::wstring path;
    ULONGLONG name_hash = 0;

    if (eid == KFE_DELETE_PATH)
    {
        parser.try_parse<std::wstring>(L"FileName", path);
        MaybePrintIH(ts, path, name_hash);
        parser.try_parse<ULONGLONG>(L"FileKey", key);

        // If event provides FileObject, print IO too
        parser.try_parse<ULONGLONG>(L"FileObject", fo);
        if (fo != 0)
            MaybePrintIO(ts, fo, name_hash);

        LogFileDeleteOperation(eid, ts, name_hash, fo, key);
        return;
    }

    if (eid == KFE_SET_DELETE)
    {
        fo = (ULONGLONG)parser.parse<PVOID>(L"FileObject");
        parser.try_parse<ULONGLONG>(L"FileKey", key);

        {
            std::lock_guard<std::mutex> lock(m_identityMutex);
            auto it = m_objToNameHash.find(fo);
            if (it != m_objToNameHash.end())
                name_hash = it->second;
        }

        // Parse done -> identity decisions first
        MaybePrintIO(ts, fo, name_hash);

        // Operation
        LogFileDeleteOperation(eid, ts, name_hash, fo, key);
        return;
    }
}

// ================= ETW =================
void EtwController::StartProviderBlocking()
{
    // ===== Process provider =====
    krabs::provider<> proc(L"Microsoft-Windows-Kernel-Process");
    proc.any(0x10);
    proc.enable_rundown_events();

    auto proc_cb = [this](const EVENT_RECORD& r, const krabs::trace_context& c)
        {
            auto eid = r.EventHeader.EventDescriptor.Id;
            if (eid != 1 && eid != 2 && eid != 15) return;

            krabs::schema s(r, c.schema_locator);
            krabs::parser p(s);
            uint64_t ts = s.timestamp().QuadPart;

            ULONG pid = 0;
            std::wstring proc_path;
            try {
                pid = p.parse<ULONG>(L"ProcessID");
                proc_path = p.parse<std::wstring>(L"ImageName");
            }
            catch (...) {}

            if (eid == 1 || eid == 15) {
                MaybePrintProcessInfo(0, ts, pid, proc_path);
            }
        };

    krabs::event_filter pf(krabs::predicates::any_event);
    pf.add_on_event_callback(proc_cb);
    proc.add_filter(pf);

    m_trace.enable(proc);

    // ===== File provider =====
    krabs::provider<> file(L"Microsoft-Windows-Kernel-File");
    file.any(0x10 | 0x20 | 0x80 | 0x200 | 0x400 | 0x800 | 0x1000);
    file.enable_rundown_events();

    auto file_cb = [this](const EVENT_RECORD& r, const krabs::trace_context& c)
        {
            krabs::schema s(r, c.schema_locator);
            krabs::parser parser(s);
            uint32_t pid = s.process_id();
            if (pid == m_curPid || pid == 4) {
                return;
            }
            uint64_t ts = s.timestamp().QuadPart;
            auto eid = s.event_id();

            try {
                if (eid == KFE_CREATE || eid == KFE_CREATE_NEW_FILE) // Create -> save to cache to retrieve file name event, also check for FILE_DELETE_ON_CLOSE (0x00001000) of CreateOptions
                {
                    HandleFileCreate(pid, eid, ts, parser);
                }
                else if (eid == KFE_CLEANUP || eid == KFE_CLOSE) //  Close, clean up -> remove from check
                {
                    HandleFileCleanup(eid, ts, parser);
                }
                else if (eid == KFE_WRITE) // Write
                {
                    HandleFileWrite(pid, eid, ts, parser);
                }
                else if (eid == KFE_RENAME_29 || eid == KFE_RENAME || eid == KFE_RENAME_PATH) // Rename
                {
                    HandleFileRename(pid, eid, ts, parser);
                }
                if (eid == KFE_SET_DELETE || eid == KFE_DELETE_PATH) // SetDelete and DeletePath 
                {
                    HandleFileDelete(pid, eid, ts, parser);
                }
            }
            catch (...) {}
        };

    krabs::event_filter ff(krabs::predicates::any_event);
    ff.add_on_event_callback(file_cb);
    file.add_filter(ff);

    m_trace.enable(file);

    m_trace.start(); // blocking
}

// ================= Lifecycle =================
void EtwController::Start()
{
    StartLoggerThread();

    m_traceThread = std::jthread([this]() {
        StartProviderBlocking();
        });
}

void EtwController::Stop()
{
    m_trace.stop();

    m_stopLogger = true;

    if (m_loggerThread.joinable())
        m_loggerThread.join();
}

#ifdef _DEBUG
void EtwController::RunDebugBlocking()
{
    StartProviderBlocking();
}
#endif
