#pragma once
#include "CoreElementParser.h"
#include "RoleMapper.h"
#include <string>
#include <vector>
#include <string>

class OwlGenerator {
public:
    void generate(const CoreElement& element, const std::string& outputPath);
private:
    RoleMapper mapper;
    std::string genKeys(const CoreElement& element);
    std::string genHashAndCorr(const CoreElement& element);
    std::string genParams(const CoreElement& element);
    std::string genMessages(const CoreElement& element);

    std::string generate_dh_hash_output(const std::string& l_value);

    static std::string genLocalityClient(const std::vector<std::string>& roles);
    static std::string genLocalityServer(const std::vector<std::string>& roles);
    static std::string genDynamicUserAndCorr(const std::vector<std::string>& roles);

    static std::string genClientProcess(const std::vector<std::string>& roles);
    static std::string genServerProcess(const std::vector<std::string>& roles);

};
