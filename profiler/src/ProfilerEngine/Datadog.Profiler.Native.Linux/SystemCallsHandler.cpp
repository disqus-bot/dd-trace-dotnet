#include "SystemCallsHandler.h"

#include "ManagedThreadInfo.h"
#include "IConfiguration.h"

thread_local ManagedThreadInfo* managedThreadInfo = nullptr;
volatile SystemCallsHandler* SystemCallsHandler::Instance = nullptr;

extern "C" int (*volatile __dd_acquire_release_barrier)(int) __attribute__((weak));

int SystemCallsHandler::gHandleSystemCalls(int state)
{
    if (Instance == nullptr)
    {
        Log::Info("Still nulll");
        return 0;
    }
    return Instance->HandleSystemCalls(state != 0);
}

SystemCallsHandler::SystemCallsHandler(IConfiguration* configuration) :
    _enabled{configuration->IsWallTimeProfilingEnabled()}
{
    Log::Info("Creating class");
    if (_enabled)
    {
        Log::Info("installing callback");
        __dd_acquire_release_barrier = SystemCallsHandler::gHandleSystemCalls;
    }
    Instance = this;
}

void SystemCallsHandler::MyThread(std::shared_ptr<ManagedThreadInfo> const& threadInfo)
{
    managedThreadInfo = threadInfo.get();
}

int SystemCallsHandler::HandleSystemCalls(bool acquireRelease) volatile
{
    if (!_enabled)
    {
        return 0;
    }

    auto threadInfo = managedThreadInfo;
    if (threadInfo == nullptr)
    {
        return 0;
    }

    if (acquireRelease)
    {
        threadInfo->GetStackWalkLock().Acquire();
        return 1;
    }

    threadInfo->GetStackWalkLock().Release();
    return 0;
}