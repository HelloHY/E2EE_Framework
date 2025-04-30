
#include "RoleMapper.h"

std::string RoleMapper::shorten(const std::string& role) {
    if (roleMap.count(role)) return roleMap[role];
    std::string alias(1, 'A' + counter++);
    roleMap[role] = alias;
    return alias;
}


