#pragma once

#include <memory>

class IConfiguration;
class ManagedThreadInfo;

class SystemCallsHandler
{
public:
    SystemCallsHandler(IConfiguration* configuration);

    void MyThread(std::shared_ptr<ManagedThreadInfo> const& threadInfo);

private:
    static volatile SystemCallsHandler* Instance;
    static int gHandleSystemCalls(int state);

    int HandleSystemCalls(bool acquireRelease) volatile;

    bool _enabled;
};
