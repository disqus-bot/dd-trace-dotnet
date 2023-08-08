// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include "SystemCallsShield.h"

#include "IConfiguration.h"
#include "ManagedThreadInfo.h"

#include <sys/syscall.h>
#include <unistd.h>

thread_local ManagedThreadInfo* managedThreadInfo = nullptr;
SystemCallsShield* SystemCallsShield::Instance = nullptr;

extern "C" int (*volatile __dd_acquire_release_barrier)(int) __attribute__((weak));
// check if this symbol is present to know if the wrapper is loaded
extern "C" unsigned long long dd_inside_wrapped_functions() __attribute__((weak));

SystemCallsShield::SystemCallsShield(IConfiguration* configuration) :
    _isEnabled{ShouldEnable(configuration)}
{
}

bool SystemCallsShield::ShouldEnable(IConfiguration* configuration)
{
    // Make sure the wrapper is present.
    // Walltime and CPU profilers are the only ones that could interrupt a system calls
    // (It might not be obvious, for the CPU profiler we could be in a race)
    return dd_inside_wrapped_functions != nullptr && (configuration->IsWallTimeProfilingEnabled() || configuration->IsCpuProfilingEnabled());
}

bool SystemCallsShield::Start()
{
    if (_isEnabled)
    {
        Instance = this;
        __dd_acquire_release_barrier = SystemCallsShield::HandleSystemCalls;
    }

    return true;
}

bool SystemCallsShield::Stop()
{
    if (_isEnabled)
    {
        __dd_acquire_release_barrier = nullptr;
        Instance = nullptr;
    }

    return true;
}

const char* SystemCallsShield::GetName()
{
    return "Linux System Calls Shield";
}

void SystemCallsShield::Register(std::shared_ptr<ManagedThreadInfo> const& threadInfo)
{
    if (_isEnabled)
    {
        managedThreadInfo = threadInfo.get();
    }
}

void SystemCallsShield::Unregister()
{
    if (_isEnabled)
    {
        managedThreadInfo = nullptr;
    }
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
    auto threadInfo = managedThreadInfo;
    if (threadInfo == nullptr)
    {
        return 0;
    }

    static thread_local int InThere = 0;
    if (acquireOrRelease)
    {
        if (InThere++ > 0)
        {
            return 1;
        }

        threadInfo->GetStackWalkLock().Acquire();
        threadInfo->_safeToInterrupt = false;
        threadInfo->GetStackWalkLock().Release();
        return 1;
    }

    InThere--;
    if (InThere == 0)
    {
        threadInfo->_safeToInterrupt = true;
    }

    return 0;
}