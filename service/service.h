#ifdef _WIN32

#ifndef SERVICE_SERVICE_H_
#define SERVICE_SERVICE_H_

/*
C/C++ -> General -> Additional Include Dir -> $(ProjectDir)
*/

#include "ulti/support.h"
#include "ulti/debug.h"

#define SERVICE_CONTROL_START 128
#define SERVICE_CONTROL_HIEUNT_ACCEPT_STOP 129
#define SERVICE_CONTROL_HIEUNT_BLOCK_STOP 130

constexpr auto SERVICE_NAME = L"HieuNTEtw";

namespace srv
{
	class Service
	{
	private:
		std::wstring service_name_;
		std::wstring service_path_;
		SC_HANDLE h_services_control_manager_ = NULL;
		DWORD type_ = NULL;
		DWORD start_type_ = NULL;

		static Service* instance_;
		static std::vector<PVOID> unload_funcs_;
		static PVOID service_main_;

	public:

		Service() = default;

		DWORD Create(const std::wstring& service_path, const DWORD& type, const DWORD& start_type);
		DWORD Run();
		DWORD Stop();
		DWORD Delete();

		Service(const std::wstring& name);

		~Service();

		static Service* GetInstance();
		static void FreeInstance();

		static void RegisterService();

		static void RegisterUnloadFunc(PVOID fn);
		static void ServiceMain();
		static void StartServiceMain(PVOID fn);

		static void ServiceCtrlHandler(DWORD ctrl_code);
		static void InitServiceCtrlHandler();
	};

}

#endif // SERVICE_SERVICE_H_

#endif // _WIN32