// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#pragma once

#include <list>
#include <mutex>

#include "corprof.h"
#include "IBatchedSamplesProvider.h"
#include "ISampledAllocationsListener.h"
#include "IService.h"
#include "Sample.h"

class IManagedThreadList;
class IFrameStore;
class IThreadsCpuManager;
class IAppDomainStore;
class IRuntimeIdStore;
class IConfiguration;
class ISampledAllocationsListener;


class LiveObjectsProvider : public IService,
                            public IBatchedSamplesProvider,
                            public ISampledAllocationsListener
{
public:
    static std::vector<SampleValueType> SampleTypeDefinitions;

public:
    LiveObjectsProvider(
        uint32_t valueOffset,
        ICorProfilerInfo4* pCorProfilerInfo,
        IFrameStore* pFrameStore,
        IAppDomainStore* pAppDomainStore,
        IRuntimeIdStore* pRuntimeIdStore,
        IConfiguration* pConfiguration);

public:
    // Inherited via IService
    virtual bool Start() override;
    virtual bool Stop() override;

    // Inherited via IBatchedSamplesProvider
    virtual std::list<Sample> GetSamples() override;
    virtual const char* GetName() override;

    // Inherited via ISampledAllocationsListener
    virtual void OnAllocation(RawAllocationSample& rawSample) override;

    void OnGarbageCollectionStarted();
    void OnGarbageCollectionFinished();

private:
    uint32_t _valueOffset = 0;
    ICorProfilerInfo4* _pCorProfilerInfo = nullptr;
    IFrameStore* _pFrameStore = nullptr;
    IAppDomainStore* _pAppDomainStore = nullptr;
    IRuntimeIdStore* _pRuntimeIdStore = nullptr;
    IThreadsCpuManager* _pThreadsCpuManager = nullptr;

    bool _isTimestampsAsLabelEnabled = false;

    std::mutex _samplesLock;

    // std::list<>
};
