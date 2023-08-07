// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#pragma once

#include "IConfiguration.h"

#include <string>
#include <vector>

class IMetadataProvider
{
public:
    virtual void Initialize(IConfiguration* configuration) = 0;
    virtual void Add(std::string section, std::string key, std::string value) = 0;
    virtual std::vector<std::pair<std::string, std::vector<std::pair<std::string, std::string>>>>& Get() = 0;

    virtual ~IMetadataProvider() = default;
};