#include "ulti/support.h"
#include "service/service.h"

using namespace std;

void PrintAllProp(krabs::schema schema, krabs::parser& parser) { std::wcout << L"task_name=" << schema.task_name() << ", "; std::wcout << L"PID=" << schema.process_id() << ", "; for (const auto& x : parser.properties()) { wstring wstr; try { wstr = parser.parse<std::wstring>(x.name()); } catch (...) { UINT64 num = 0; try { wstr = to_wstring(parser.parse<UINT64>(x.name())); } catch (...) { try { wstr = to_wstring(parser.parse<UINT32>(x.name())); } catch (...) { try { wstr = to_wstring(parser.parse<UINT16>(x.name())); } catch (...) { try { wstr = to_wstring(parser.parse<UINT8>(x.name())); } catch (...) {} } } } } if (wstr.size() != 0) { wcout << x.name() << " " << wstr << ", "; } } cout << endl; }

krabs::user_trace trace(L"hieunt");

std::mutex g_lockProc, g_lockFile, g_logMutex;
std::queue<std::wstring> g_logQueue;
bool g_stopLogger = false;

struct FileWrite {
    std::wstring path;
    bool written = false;
};

std::unordered_map<DWORD, std::wstring> g_pidToPath;
std::unordered_map<PVOID, FileWrite> g_fileObjectToName;

struct CanCalEvent {
    LONGLONG time_stamp;
    ULONG pid;
    std::wstring process_path;
    std::wstring operation;
    std::wstring file_path;
};

void PushLog(const std::wstring& s)
{
    g_logMutex.lock();
    g_logQueue.push(s);
    g_logMutex.unlock();
}

void LoggerThread()
{
    while(true)
    {
        Sleep(5000);
        if (g_stopLogger) break;
        std::lock_guard<std::mutex> l(g_logMutex);
        if (g_logQueue.size() == 0) continue;
        if (g_logQueue.size() >= 10000)
            g_logQueue = std::queue<std::wstring>();
        std::wofstream ofs(L"C:\\hieunt_log.jsonl", std::ios::app);
        if (!ofs.is_open()) continue;
        std::queue<std::wstring> local;
        local.swap(g_logQueue);
        while (!local.empty())
        {
            ofs << local.front() << L"\n";
            local.pop();
        }
    }
}

auto cur_pid = GetCurrentProcessId();

void AddEvent(ULONG pid, const WCHAR* operation, const std::wstring& file_path)
{
    if (file_path.size() == 0 || pid == 4 || pid == 0 || pid == cur_pid)
    {
        return;
    }
    wstring process_path;
    g_lockProc.lock();
    auto it = g_pidToPath.find(pid);
    process_path = (it != g_pidToPath.end()) ? it->second : L"";
    g_lockProc.unlock();
    if (process_path.size() == 0)
    {
        return;
    }
    FILETIME ft = { 0,0 };
    GetSystemTimeAsFileTime(&ft);
    LONGLONG time_stamp = ((LONGLONG)(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    CanCalEvent e;
    e.pid = pid;
    e.process_path = process_path;
    e.operation = operation;
    e.file_path = file_path;
    e.time_stamp = time_stamp;

    std::wstringstream ss;
    ss << L"{"
        << L"\"Time\":" << e.time_stamp << L","
        << L"\"Pid\":" << e.pid << L","
        << L"\"Pid_path\":\"" << e.process_path << L"\","
        << L"\"Operation\":\"" << e.operation << L"\","
        << L"\"File_path\":\"" << e.file_path << L"\""
        << L"}";

    std::wcout << ss.str() << endl;
    PushLog(ss.str());
}

void StartProvider()
{
    krabs::provider<> process_provider(L"Microsoft-Windows-Kernel-Process");
    process_provider.any(0x10);  // WINEVENT_KEYWORD_PROCESS
    process_provider.enable_rundown_events();

    auto process_callback = [](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        auto eid = record.EventHeader.EventDescriptor.Id;
        if (eid != 1 && eid != 2 && eid != 15)
        {
            return;
        }
        krabs::schema schema(record, trace_context.schema_locator);
        krabs::parser parser(schema);
        uint32_t pid = parser.parse<uint32_t>(L"ProcessID");
        std::lock_guard<std::mutex> l(g_lockProc);
        if (eid == 1 || eid == 15)
        {
            std::wstring image_name = parser.parse<std::wstring>(L"ImageName");
            g_pidToPath[pid] = image_name;
        }
        else if (eid == 2)
        {
            g_pidToPath.erase(pid);
        }
        };

    krabs::event_filter process_filter(krabs::predicates::any_event);
    process_filter.add_on_event_callback(process_callback);
    process_provider.add_filter(process_filter);

    trace.enable(process_provider);
    
    krabs::provider<> file_provider(L"Microsoft-Windows-Kernel-File");
    file_provider.any(0
        | 0x10      // KERNEL_FILE_KEYWORD_FILENAME
        | 0x20      // KERNEL_FILE_KEYWORD_FILEIO
        | 0x80      // KERNEL_FILE_KEYWORD_CREATE
        | 0x200     // KERNEL_FILE_KEYWORD_WRITE
        | 0x400     // KERNEL_FILE_KEYWORD_DELETE_PATH
        | 0x800     // KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH
        | 0x1000    // KERNEL_FILE_KEYWORD_CREATE_NEW_FILE
    );
    file_provider.enable_rundown_events();

    auto file_callback = [](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        krabs::parser parser(schema);
        uint32_t pid = schema.process_id();
        auto event_id = schema.event_id();
        if (event_id == 12 || event_id == 30) // Create -> save to cache to retrieve file name for write event, also check for FILE_DELETE_ON_CLOSE (0x00001000) of CreateOptions
        {
            auto fo = parser.parse<PVOID>(L"FileObject");
            auto fn = parser.parse<std::wstring>(L"FileName");
            auto co = parser.parse<UINT32>(L"CreateOptions");
            g_fileObjectToName[fo] = { fn, false };
            if ((co & 0x00001000) != 0) // FILE_DELETE_ON_CLOSE
            {
                // Delete event
                AddEvent(pid, L"Delete", fn);
                
            }
            if (event_id == 30)
            {
                // Create event
                AddEvent(pid, L"Create", fn);
            }
        }
        else if (event_id == 13 || event_id == 14) //  Close, clean up -> remove from check
        {
            auto fo = parser.parse<PVOID>(L"FileObject");
            g_fileObjectToName.erase(fo);

        }
        else if (event_id == 16) // Write
        {
            auto fo = parser.parse<PVOID>(L"FileObject");
            if (g_fileObjectToName.find(fo) == g_fileObjectToName.end()) return;
            auto& pwb = g_fileObjectToName[fo];
            if (pwb.written == true) return;
            pwb.written = true;
            const auto& fn = pwb.path;
            
            // Write event
            AddEvent(pid, L"Write", fn);
        }
        else if (event_id == 29 || event_id == 19 || event_id == 27) // Rename
        {
            std::wstring fn;
            if (event_id == 27)
            {
                parser.try_parse<std::wstring>(L"FileName", fn);
            }
            else
            {
                auto fo = parser.parse<PVOID>(L"FileObject");
                if (g_fileObjectToName.find(fo) == g_fileObjectToName.end()) return;
                fn = g_fileObjectToName[fo].path;
            }

            // Rename event
            AddEvent(pid, L"Rename", fn);
        }
        if (event_id == 18 || event_id == 26) // SetDelete and DeletePath 
        {
            std::wstring fn;
            if (event_id == 26)
            {
                parser.try_parse<std::wstring>(L"FileName", fn);
            }
            else if (event_id == 18)
            {
                auto fo = parser.parse<PVOID>(L"FileObject");
                if (g_fileObjectToName.find(fo) == g_fileObjectToName.end()) return;
                fn = g_fileObjectToName[fo].path;
            }

            // Delete event
            AddEvent(pid, L"Delete", fn);
        }

    };

    krabs::event_filter file_filter(krabs::predicates::any_event);
    file_filter.add_on_event_callback(file_callback);
    file_provider.add_filter(file_filter);

    trace.enable(file_provider);

    trace.start();
}

std::thread logger_thread;
std::jthread trace_thread;

void Start()
{
    std::thread logger_thread(LoggerThread);

    std::jthread trace_thread([]() {
        StartProvider();
        });
}

void Stop()
{
    trace.stop();
    {
        std::lock_guard<std::mutex> l(g_logMutex);
        g_stopLogger = true;
    }
    logger_thread.join();
}

int main() {

    if (ulti::IsRunningAsSystem() == false)
    {
        srv::Service::RegisterService();
    }
    else
    {
        srv::Service::RegisterUnloadFunc(Stop);
        srv::Service::StartServiceMain(Start);
    }

}