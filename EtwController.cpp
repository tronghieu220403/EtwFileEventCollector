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
    : m_curPid(GetCurrentProcessId())
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
    ss << L"event_id=" << schema.event_id() << L", ";
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

    if (ss.str().find(L"load\\test") != std::wstring::npos)
        wcout << ss.str() << endl;
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

// ================= IH Cache =================
// Add or update an IH cache entry.
// - Increase ref_count if the entry already exists
// - Update last_used timestamp
// - Perform eviction if the cache is full
void EtwController::IHCacheAdd(ULONGLONG ts, const std::wstring& path, ULONGLONG name_hash)
{
    auto& cache = m_ihCache;

    // Fast path: entry already exists
    auto it = cache.find(name_hash);
    if (it != cache.end()) {
        it->second.ref_count++;
        it->second.last_used_ts = ts;
        return;
    }

    // Evict if cache reaches capacity
    if (cache.size() >= MAX_CACHE_SIZE) {
        auto victim = cache.end();

        // First pass: evict the least-recently-used entry with ref_count == 0
        for (auto it2 = cache.begin(); it2 != cache.end(); ++it2) {
            if (it2->second.ref_count == 0) {
                if (victim == cache.end() ||
                    it2->second.last_used_ts < victim->second.last_used_ts) {
                    victim = it2;
                }
            }
        }

        // Second pass: if no zero-ref entry exists, evict pure LRU
        if (victim == cache.end()) {
            for (auto it2 = cache.begin(); it2 != cache.end(); ++it2) {
                if (victim == cache.end() ||
                    it2->second.last_used_ts < victim->second.last_used_ts) {
                    victim = it2;
                }
            }
        }

        if (victim != cache.end())
            cache.erase(victim);
    }

    // Insert new cache entry
    cache.emplace(
        name_hash,
        IHEntry{
            path,
            1,          // initial reference
            ts
        }
    );
}

// Decrease reference count of an IH cache entry.
// If the entry does not exist, silently ignore.
void EtwController::IHCacheRelease(ULONGLONG name_hash)
{
    auto it = m_ihCache.find(name_hash);
    if (it == m_ihCache.end())
        return;

    if (it->second.ref_count > 0)
        it->second.ref_count--;
}

// Cache identity information (IH) without printing it.
// This function only:
//  - Computes name_hash
//  - Adds the entry to IHCache
// Logging is deferred until a real file operation occurs.
bool EtwController::AddToIHCache(ULONGLONG ts, const std::wstring& path, ULONGLONG& out_name_hash)
{
    out_name_hash = 0;
    if (path.empty())
        return false;

    std::wstring lower = ulti::ToLower(path);
    ULONGLONG name_hash = helper::GetWstrHash(lower);
    out_name_hash = name_hash;

    std::lock_guard<std::mutex> lock(m_identityMutex);

    // If this IH has already been printed, skip completely
    if (m_printedNameHash.contains(name_hash))
        return false;

    // Otherwise, cache it and increase reference count
    IHCacheAdd(ts, lower, name_hash);
    return true;
}

// Materialize (print) an IH entry.
// This should be called right before a guaranteed file operation log.
// Once printed, the entry is:
//  - Inserted into printedNameHash LRU
//  - Removed from IHCache regardless of ref_count
void EtwController::MaybePrintIH(ULONGLONG name_hash)
{
    std::lock_guard<std::mutex> lock(m_identityMutex);
    auto it = m_ihCache.find(name_hash);
    if (it == m_ihCache.end()) {
        return;
    }

    // Already printed -> nothing to do
    if (m_printedNameHash.contains(name_hash) == true) {
        return;
    }

    const auto& entry = it->second;

    std::wstringstream ss;
    ss << L"F,IH,0,0," << name_hash << L"," << entry.path;
    PushLog(ss.str());

    // Update printed IH LRU cache
    m_printedNameHash.insert(name_hash);

    // Remove from IHCache after materialization
    m_ihCache.erase(it);
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

void EtwController::TrackProcess(ULONG pid, const std::wstring& path)
{
    if (pid == 0 || path.empty())
        return;

    std::lock_guard<std::mutex> lock(m_lockProc);
    m_pidToPath[pid] = path;
}

std::wstring EtwController::GetTrackedProcessPath(ULONG pid)
{
    if (pid == 0)
        return L"";

    {
        std::lock_guard<std::mutex> lock(m_lockProc);
        auto it = m_pidToPath.find(pid);
        if (it != m_pidToPath.end() && !it->second.empty())
            return it->second;
    }

    return ulti::GetProcessPath(pid);
}

bool EtwController::IsEdgeProcessPath(const std::wstring& path)
{
    if (path.empty())
        return false;

    const std::wstring lower = ulti::ToLower(path);
    const std::wstring edge_name = L"msedge.exe";

    if (lower == edge_name)
        return true;

    if (lower.size() < edge_name.size())
        return false;

    const size_t pos = lower.size() - edge_name.size();
    if (lower.compare(pos, edge_name.size(), edge_name) != 0)
        return false;

    return pos == 0 || lower[pos - 1] == L'\\' || lower[pos - 1] == L'/';
}

std::wstring EtwController::ParseProcessImageName(krabs::parser& parser)
{
    try {
        std::wstring path;
        if (parser.try_parse<std::wstring>(L"ImageName", path) && !path.empty())
            return path;
    }
    catch (...) {

    }

    try {
        std::string ansi_path;
        if (parser.try_parse<std::string>(L"ImageName", ansi_path) && !ansi_path.empty())
            return ulti::StrToWstr(ansi_path);
    }
    catch (...) {

    }

    return L"";
}

void EtwController::LogEdgeTerminateAttempt(ULONGLONG ts, ULONG source_pid, ULONG target_pid, ULONG return_code)
{
    std::wstring target_path = GetTrackedProcessPath(target_pid);
    if (!IsEdgeProcessPath(target_path))
        return;

    std::wstring source_path = GetTrackedProcessPath(source_pid);

    wcout << L"KILL" << ts
       << L"," << source_pid
       << L"," << source_path
       << L"," << target_pid
       << L"," << target_path
       << L"," << return_code << endl << endl;
}

// ================= Identity logging =================
void EtwController::MaybePrintIO(ULONGLONG file_object, ULONGLONG name_hash)
{
    if (file_object == 0 || name_hash == 0)
        return;
    
    std::lock_guard<std::mutex> lock(m_identityMutex);
    if (m_printedObj.contains(file_object) == true) {
        return;
    }
    
    std::wstringstream ss;
    ss << L"F,IO,0," << file_object << L"," << name_hash;
    PushLog(ss.str());

    m_printedObj.insert(file_object);
}

void EtwController::ForcePrintIK(ULONG eid, ULONGLONG file_key, ULONGLONG name_hash)
{
    if (file_key == 0 || name_hash == 0)
        return;

    std::wstringstream ss;
    ss << L"F,IK," << eid << L"," << file_key << L"," << name_hash;
    PushLog(ss.str());
}

// ================= File operation logging =================
void EtwController::LogFileCreateOperation(ULONG pid, ULONG eid, ULONGLONG ts, ULONGLONG name_hash)
{
    std::wstringstream ss;
    ss << L"F,C," << eid << L"," << pid << L"," << ts << L"," << name_hash;
    PushLog(ss.str());
}

void EtwController::LogFileWriteOperation(ULONG pid, ULONG eid, ULONGLONG ts, ULONGLONG file_object)
{
    std::wstringstream ss;
    ss << L"F,W," << eid << L"," << pid << L"," << ts << L"," << file_object;
    PushLog(ss.str());
}

void EtwController::LogFileRenameOperation(ULONG pid, ULONG eid, ULONGLONG ts, ULONGLONG name_hash, ULONGLONG file_object, ULONGLONG file_key)
{
    std::wstringstream ss;
    ss << L"F,RN," << eid << L"," << pid << L"," << ts << L"," << name_hash << L"," << file_object << L"," << file_key;
    PushLog(ss.str());
}

void EtwController::LogFileDeleteOperation(ULONG pid, ULONG eid, ULONGLONG ts, ULONGLONG name_hash, ULONGLONG file_object, ULONGLONG file_key)
{
    std::wstringstream ss;
    ss << L"F,D," << eid << L"," << pid << L"," << ts << L"," << name_hash << L"," << file_object << L"," << file_key;
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
    AddToIHCache(ts, path, name_hash);

    // Manage object table for later lookups
    {
        std::lock_guard<std::mutex> lock(m_identityMutex);
        m_objToNameHash[fo] = name_hash;
        m_printedWriteObj.erase(fo);
    }

    // Operation
    if (eid == KFE_CREATE_NEW_FILE)
    {
        MaybePrintIH(name_hash);
        MaybePrintIO(fo, name_hash);
        LogFileCreateOperation(pid, eid, ts, name_hash);
    }

    // Delete-on-close mapped to delete operation without file key
    if ((co & 0x00001000) != 0)
    {
        MaybePrintIH(name_hash);
        MaybePrintIO(fo, name_hash);
        LogFileDeleteOperation(pid, eid, ts, name_hash, fo, 0);
    }
}

void EtwController::HandleFileCleanup(ULONG eid, ULONGLONG ts, krabs::parser& parser)
{
    ULONGLONG fo = (ULONGLONG)parser.parse<PVOID>(L"FileObject");
    {
        std::lock_guard<std::mutex> lock(m_identityMutex);
        m_objToNameHash.erase(fo);
        m_printedObj.erase(fo);
        m_printedWriteObj.erase(fo);
    }
}

void EtwController::HandleFileWrite(ULONG pid, ULONG eid, ULONGLONG ts, krabs::parser& parser)
{
    ULONGLONG fo = (ULONGLONG)parser.parse<PVOID>(L"FileObject");

    m_identityMutex.lock();
    if (m_printedWriteObj.contains(fo) == true) {
        m_identityMutex.unlock();
        return;
    }
    m_identityMutex.unlock();

    // Parse done -> identity decisions first (IO requires name_hash, resolve via obj table)
    ULONGLONG name_hash = 0;
    {
        std::lock_guard<std::mutex> lock(m_identityMutex);
        auto it = m_objToNameHash.find(fo);
        if (it != m_objToNameHash.end())
            name_hash = it->second;
    }
    MaybePrintIH(name_hash);
    MaybePrintIO(fo, name_hash);

    // Operation
    LogFileWriteOperation(pid, eid, ts, fo);
    m_identityMutex.lock();
    m_printedWriteObj.insert(fo);
    m_identityMutex.unlock();
}

void EtwController::HandleFileRename(ULONG pid, ULONG eid, ULONGLONG ts, krabs::parser& parser) // File name in 19 rename to file name in event 27
{
    ULONGLONG fo = 0;
    ULONGLONG key = 0;
    std::wstring path;
    ULONGLONG name_hash = 0;

    if (eid == KFE_RENAME_PATH)
    {
        parser.try_parse<std::wstring>(L"FilePath", path);
        AddToIHCache(ts, path, name_hash);
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
    MaybePrintIH(name_hash);

    parser.try_parse<ULONGLONG>(L"FileKey", key);

    // Parse done -> identity decisions first
    if (fo != 0)
        MaybePrintIO(fo, name_hash);

    // Operation
    LogFileRenameOperation(pid, eid, ts, name_hash, fo, key);
}

void EtwController::HandleFileDelete(ULONG pid, ULONG eid, ULONGLONG ts, krabs::parser& parser)
{
    ULONGLONG fo = 0;
    ULONGLONG key = 0;
    std::wstring path;
    ULONGLONG name_hash = 0;

    switch (eid) {
    case KFE_NAME_DELETE:
        parser.try_parse<ULONGLONG>(L"FileKey", key);
        parser.try_parse<std::wstring>(L"FileName", path);

        AddToIHCache(ts, path, name_hash);
        MaybePrintIH(name_hash);
        ForcePrintIK(eid, key, name_hash);
        
        break;

    case KFE_DELETE_PATH:
        parser.try_parse<std::wstring>(L"FileName", path);
        AddToIHCache(ts, path, name_hash);
        MaybePrintIH(name_hash);
        parser.try_parse<ULONGLONG>(L"FileKey", key);

        // If event provides FileObject, print IO too
        parser.try_parse<ULONGLONG>(L"FileObject", fo);
        if (fo != 0)
            MaybePrintIO(fo, name_hash);
        LogFileDeleteOperation(pid, eid, ts, name_hash, fo, key);

        break;

    case KFE_SET_DELETE:
        fo = (ULONGLONG)parser.parse<PVOID>(L"FileObject");
        parser.try_parse<ULONGLONG>(L"FileKey", key);

        {
            std::lock_guard<std::mutex> lock(m_identityMutex);
            auto it = m_objToNameHash.find(fo);
            if (it != m_objToNameHash.end())
                name_hash = it->second;
        }
        MaybePrintIH(name_hash);

        // Parse done -> identity decisions first
        MaybePrintIO(fo, name_hash);

        // Operation
        LogFileDeleteOperation(pid, eid, ts, name_hash, fo, key);

        break;

    default:
        break;
    }
}

// ================= ETW =================
void EtwController::StartProviderBlocking()
{
    // ===== Process provider: keeps PID -> image path fresh, including rundown =====
    krabs::provider<> proc(L"Microsoft-Windows-Kernel-Process");
    proc.any(0x10);
    proc.enable_rundown_events();

    auto proc_cb = [this](const EVENT_RECORD& r, const krabs::trace_context& c)
        {
            const auto eid = r.EventHeader.EventDescriptor.Id;
            if (eid != 1 && eid != 2 && eid != 15)
                return;

            krabs::schema s(r, c.schema_locator);
            krabs::parser p(s);

            ULONG pid = 0;
            if (!p.try_parse<ULONG>(L"ProcessID", pid))
                return;

            const std::wstring proc_path = ParseProcessImageName(p);
            TrackProcess(pid, proc_path);
        };

    krabs::event_filter pf(krabs::predicates::any_event);
    pf.add_on_event_callback(proc_cb);
    proc.add_filter(pf);
    m_userTrace.enable(proc);

    // ===== Audit API provider: event id 2 is TerminateProcess =====
    krabs::provider<> audit(L"Microsoft-Windows-Kernel-Audit-API-Calls");
    audit.level(TRACE_LEVEL_VERBOSE);

    auto audit_cb = [this](const EVENT_RECORD& r, const krabs::trace_context& c)
        {
            krabs::schema s(r, c.schema_locator);
            if (s.event_id() != KERNEL_AUDIT_API_TERMINATEPROCESS)
                return;

            krabs::parser p(s);

            ULONG target_pid = 0;
            ULONG return_code = 0;
            if (!p.try_parse<ULONG>(L"TargetProcessId", target_pid))
                return;

            p.try_parse<ULONG>(L"ReturnCode", return_code);

            const ULONG source_pid = s.process_id();
            if (source_pid == m_curPid)
                return;

            LogEdgeTerminateAttempt(s.timestamp().QuadPart, source_pid, target_pid, return_code);
        };

    krabs::event_filter af(krabs::predicates::any_event);
    af.add_on_event_callback(audit_cb);
    audit.add_filter(af);
    m_userTrace.enable(audit);

    m_userTrace.start(); // blocking
}

// ================= Lifecycle =================
void EtwController::Start()
{
    m_userTraceThread = std::jthread([this]() {
        StartProviderBlocking();
        });
}

void EtwController::Stop()
{
    m_userTrace.stop();

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
