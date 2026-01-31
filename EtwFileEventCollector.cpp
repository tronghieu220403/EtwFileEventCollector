#include "EtwController.h"
#include "ulti/support.h"
#include "service/service.h"

int main()
{
#ifdef _DEBUG
    //EtwController::GetInstance()->RunDebugBlocking();
    EtwController::StartThunk();
    Sleep(INFINITE);
#else
    // Service mode
    if (!ulti::IsRunningAsSystem())
    {
        srv::Service::RegisterService();
    }
    else
    {
        srv::Service::RegisterUnloadFunc(EtwController::StopThunk);
        srv::Service::StartServiceMain(EtwController::StartThunk);
    }
#endif
    return 0;
}
