#ifdef _WIN32

#include "service.h"

namespace srv
{
	DWORD Service::Create(const std::wstring& service_path, const DWORD& type, const DWORD& start_type)
	{
		if (h_services_control_manager_ == NULL) {
			PrintDebugW(L"Failed to open Service Control Manager");
			return ERROR_INVALID_HANDLE;
		}
		type_ = type;
		start_type_ = start_type;
		service_path_ = service_path;

		SC_HANDLE handle_service = OpenServiceW(h_services_control_manager_, service_name_.c_str(), SERVICE_QUERY_STATUS);
		if (handle_service != NULL)
		{
			return ERROR_SERVICE_EXISTS;
		}

		handle_service = CreateServiceW(h_services_control_manager_, service_name_.c_str(), service_name_.c_str(),
			SERVICE_ALL_ACCESS, type_,
			start_type_, SERVICE_ERROR_NORMAL,
			service_path_.c_str(), NULL, NULL, NULL, NULL, NULL);

		if (handle_service == NULL)
		{
			ULONG status = GetLastError();
			if (status == ERROR_DUPLICATE_SERVICE_NAME || status == ERROR_SERVICE_EXISTS)
			{
				return status;
			}
			return status;
		}
		CloseServiceHandle(handle_service);

		return ERROR_SUCCESS;
	}

	DWORD Service::Run()
	{
		if (h_services_control_manager_ == NULL) {
			PrintDebugW(L"Failed to open Service Control Manager");
			return ERROR_INVALID_HANDLE;
		}

		SC_HANDLE handle_service;
		std::wstring working_dir;
		working_dir.resize(MAX_PATH + 1);

		GetCurrentDirectoryW(MAX_PATH + 1, &working_dir[0]);
		LPCWSTR argv_start[] = { &service_name_[0], &working_dir[0] };

		handle_service = OpenServiceW(h_services_control_manager_, service_name_.data(), SERVICE_ALL_ACCESS);

		if (handle_service == NULL)
		{
			return GetLastError();
		}

		if (!StartServiceW(handle_service, 2, argv_start))
		{
			return GetLastError();
		}
		CloseServiceHandle(handle_service);
		return ERROR_SUCCESS;
	}

	DWORD Service::Stop()
	{
		if (h_services_control_manager_ == NULL) {
			PrintDebugW(L"Failed to open Service Control Manager");
			return ERROR_INVALID_HANDLE;
		}

		if (ulti::IsRunningAsSystem() == false)
		{
			std::string stop_srv_cmd = "sc stop " + ulti::WstrToStr(service_name_);
			std::system(stop_srv_cmd.c_str());
		}

		// Open the service to stop and delete.
		SC_HANDLE service_handle = OpenService(h_services_control_manager_, service_name_.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
		if (service_handle == NULL) {
			PrintDebugW(L"Failed to open service %ws: %d", service_name_.c_str(), GetLastError());
			return GetLastError();
		}

		// Check the status of the service.
		SERVICE_STATUS status;
		if (!QueryServiceStatus(service_handle, &status)) {
			PrintDebugW(L"Failed to query service status %ws: %d", service_name_.c_str(), GetLastError());
			CloseServiceHandle(service_handle);
			return GetLastError();
		}

		// If the service is running, stop the service.
		if (status.dwCurrentState == SERVICE_RUNNING) {
			if (!ControlService(service_handle, SERVICE_CONTROL_STOP, &status)) {
				PrintDebugW(L"Failed to stop the service %ws: %d", service_name_.c_str(), GetLastError());
				CloseServiceHandle(service_handle);
				return GetLastError();
			}
		}

		CloseServiceHandle(service_handle);
		return ERROR_SUCCESS;
	}

	DWORD Service::Delete()
	{
		if (h_services_control_manager_ == NULL) {
			PrintDebugW(L"Failed to open Service Control Manager");
			return ERROR_INVALID_HANDLE;
		}

		DWORD err = ERROR_SUCCESS;
		SC_HANDLE service = OpenService(h_services_control_manager_, service_name_.c_str(), DELETE);
		if (service)
		{
			// Delete the service
			if (DeleteService(service) == FALSE)
			{
				err = GetLastError();
				PrintDebugW(L"DeleteService %ws  failed with error %d, %ws", service_name_.c_str(), err, debug::GetErrorMessage(err).c_str());
			}
			else
			{
				// Recursively delete all subkeys
				LONG result = RegDeleteTreeW(HKEY_LOCAL_MACHINE, (std::wstring(L"SYSTEM\\ControlSet001\\Services\\") + service_name_).c_str());
			}

			CloseServiceHandle(service);
		}
		else
		{
			err = GetLastError();
			PrintDebugW(L"OpenService %ws failed with error %d, %ws", service_name_.c_str(), err, debug::GetErrorMessage(err).c_str());
		}
		if (ulti::IsRunningAsSystem() == false)
		{
			std::string delete_srv_cmd = "sc delete " + ulti::WstrToStr(service_name_);
			std::system(delete_srv_cmd.c_str());
		}
		return err;
	}

	Service::Service(const std::wstring& name)
		: service_name_(name),
		h_services_control_manager_(OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS))
	{
		if (h_services_control_manager_ == NULL) {
			auto err = GetLastError();
			PrintDebugW(L"Failed to open Service Control Manager: %d, %ws", err, debug::GetErrorMessage(err).c_str());
		}
	}

	Service::~Service()
	{
		if (h_services_control_manager_ != NULL)
		{
			CloseServiceHandle(h_services_control_manager_);
		}
		h_services_control_manager_ = 0;
	}

	Service* Service::instance_ = nullptr;
	std::vector<PVOID> Service::unload_funcs_;
	PVOID Service::service_main_ = nullptr;

	Service* Service::GetInstance()
	{
		if (!instance_) instance_ = new Service(SERVICE_NAME);
		return instance_;
	}

	void Service::FreeInstance()
	{
		delete instance_;
		instance_ = nullptr;
	}

	void Service::RegisterService()
	{
		auto service = srv::Service::GetInstance();
		if (service == nullptr)
		{
			return;
		}
		ShowWindow(GetConsoleWindow(), SW_HIDE);
		service->Stop();
		service->Delete();
		std::wstring w_srv_path;
		w_srv_path.resize(1024);
		GetModuleFileNameW(nullptr, &w_srv_path[0], 1024);
		w_srv_path.resize(wcslen(&w_srv_path[0]));
		auto status = service->Create(w_srv_path, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START);
		if (status == ERROR_SUCCESS || status == ERROR_DUPLICATE_SERVICE_NAME || status == ERROR_SERVICE_EXISTS)
		{
			auto status = service->Run();
			if (status != ERROR_SUCCESS)
			{
				PrintDebugW(L"Service run failed %d", status);
			}
		}
	}

	void Service::RegisterUnloadFunc(PVOID fn)
	{
		if (fn) unload_funcs_.push_back(fn);
	}

	void Service::ServiceMain()
	{
		auto service = srv::Service::GetInstance();
		if (service == nullptr)
		{
			return;
		}
		service->InitServiceCtrlHandler();

		if (service_main_)
			reinterpret_cast<void(*)()>(service_main_)();
	}

	void Service::StartServiceMain(PVOID fn)
	{
		service_main_ = fn;
		SERVICE_TABLE_ENTRYW service_table[] = {
		{ (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONW)Service::ServiceMain},
		{ nullptr, nullptr }
			};

			if (!StartServiceCtrlDispatcher(service_table)) {
				PrintDebugW(L"StartServiceCtrlDispatcher failed");
			}
			else {
				PrintDebugW(L"StartServiceCtrlDispatcher succeeded");
			}

		}

	inline SERVICE_STATUS_HANDLE status_handle = NULL;

	SERVICE_STATUS service_status = { 0 };
	void Service::ServiceCtrlHandler(DWORD ctrl_code)
	{
		PrintDebugW(L"Control code %d", ctrl_code);
		PrintDebugW(L"dwControlsAccepted: %x", service_status.dwControlsAccepted);
		service_status.dwWin32ExitCode = NO_ERROR;
		if (ctrl_code == SERVICE_CONTROL_HIEUNT_ACCEPT_STOP)
		{
			service_status.dwControlsAccepted |= SERVICE_ACCEPT_STOP;
			SetServiceStatus(status_handle, &service_status);
		}
		else if (ctrl_code == SERVICE_CONTROL_HIEUNT_BLOCK_STOP)
		{
			service_status.dwControlsAccepted &= ~SERVICE_ACCEPT_STOP;
			SetServiceStatus(status_handle, &service_status);
		}
		else if (ctrl_code == SERVICE_CONTROL_STOP)
		{
			/*
			Here is a quote from MSDN regarding SERVICE_CONTROL_STOP and it explains why you won't receive ANY messages after a SERVICE_CONTROL_STOP message:
			"If a service accepts this control code, it must stop upon receipt and return NO_ERROR. After the SCM sends this control code, it will not send other control codes to the service."
			*/
			/*
            A little trick to prevent the service from stopping is to rebirth the service immediately (create another thread to call this exe with parameter rebirth, recreate the service, wait for the current service die and then run it again).
			*/
			service_status.dwCurrentState = SERVICE_STOP_PENDING;
			SetServiceStatus(status_handle, &service_status);
			for (auto f : unload_funcs_)
				reinterpret_cast<void(*)()>(f)();
			FreeInstance();
			service_status.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(status_handle, &service_status);
			/*
            // However, for testing purposes, I will deny the stop code
            PrintDebugW(L"Service stop");
            service_status.dwCurrentState = SERVICE_RUNNING;
            service_status.dwWin32ExitCode = ERROR_ACCESS_DENIED;
            SetServiceStatus(status_handle, &service_status);
			*/
		}
		else if (ctrl_code == SERVICE_CONTROL_SHUTDOWN)
		{
			service_status.dwCurrentState = SERVICE_STOP_PENDING;
			SetServiceStatus(status_handle, &service_status);
			service_status.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(status_handle, &service_status);
		}
		else if (ctrl_code == SERVICE_CONTROL_START)
		{
			PrintDebugW(L"Service start");
			service_status.dwCurrentState = SERVICE_RUNNING;
			SetServiceStatus(status_handle, &service_status);
		}
		else if (ctrl_code == SERVICE_CONTROL_INTERROGATE)
		{
			SetServiceStatus(status_handle, &service_status);
		}
		else
		{
			PrintDebugW(L"Service control code %d is not handled", ctrl_code);
			service_status.dwWin32ExitCode = ERROR_CALL_NOT_IMPLEMENTED;
			SetServiceStatus(status_handle, &service_status);
		}
	}

	void Service::InitServiceCtrlHandler()
	{
		PrintDebugW(L"Begin");
		auto service = srv::Service::GetInstance();
		if (service == nullptr)
		{
			return;
		}

		service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
		service_status.dwWin32ExitCode = NO_ERROR;
		service_status.dwWaitHint = 0;
		service_status.dwControlsAccepted = SERVICE_USER_DEFINED_CONTROL | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_STOP;

		status_handle = RegisterServiceCtrlHandlerW(service->service_name_.c_str(), (LPHANDLER_FUNCTION)ServiceCtrlHandler);
		if (status_handle == NULL)
		{
			PrintDebugW(L"RegisterServiceCtrlHandler failed %d", GetLastError());
		}
		ServiceCtrlHandler(SERVICE_CONTROL_START);

	}
}

#endif