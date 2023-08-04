// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include "SystemCallsShield.h"

#include "IConfiguration.h"
#include "ManagedThreadInfo.h"

thread_local ManagedThreadInfo* managedThreadInfo = nullptr;
SystemCallsShield* SystemCallsShield::Instance = nullptr;

extern "C" int (*volatile __dd_acquire_release_barrier)(int) __attribute__((weak));

SystemCallsShield::SystemCallsShield(IConfiguration* configuration) :
    // Walltime and CPU profilers are the only ones that could interrupt a system calls
    // (It might not be obvious, for the CPU profiler we could be in a race
    _enabled{configuration->IsWallTimeProfilingEnabled() || configuration->IsCpuProfilingEnabled()}
{
}

bool SystemCallsShield::Start()
{
    if (_enabled)
    {
        __dd_acquire_release_barrier = SystemCallsShield::HandleSystemCalls;
        Instance = this;
    }

    return true;
}

bool SystemCallsShield::Stop()
{
    __dd_acquire_release_barrier = nullptr;
    Instance = nullptr;

    return true;
}

const char* SystemCallsShield::GetName()
{
    return "Linux System Calls Shield";
}

void SystemCallsShield::Register(std::shared_ptr<ManagedThreadInfo> const& threadInfo)
{
    managedThreadInfo = threadInfo.get();
}

void SystemCallsShield::Unregister()
{
    managedThreadInfo = nullptr;
}

int SystemCallsShield::HandleSystemCalls(int state)
{
    if (Instance == nullptr)
    {
        return 0;
    }
    return Instance->HandleSystemCalls(state != 0);
}

int SystemCallsShield::HandleSystemCalls(bool acquireOrRelease)
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

    if (acquireOrRelease)
    {
        threadInfo->GetStackWalkLock().Acquire();
        return 1;
    }

    threadInfo->GetStackWalkLock().Release();
    return 0;
}