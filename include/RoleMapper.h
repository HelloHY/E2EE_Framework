#pragma once
#include <string>
#include <map>

class RoleMapper {
public:
    std::string shorten(const std::string& role);
private:
    std::map<std::string, std::string> roleMap;
    int counter = 0;
};
