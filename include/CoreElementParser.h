#ifndef COREELEMENTPARSER_H
#define COREELEMENTPARSER_H

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>

// CoreElement 类声明
class CoreElement {
public:
   // 客户端角色列表
   std::vector<std::string> clients;
   // 服务器角色列表
   std::vector<std::string> servers;

    // DH keys
    std::map<std::string, std::vector<std::string>> dh_keys;

    // Signature keys
    std::unordered_map<std::string, std::vector<std::string>> sig_keys;

    // parameters
    std::map<std::string, std::vector<std::string>> parameters;

    // messages
    std::unordered_map<std::string, std::vector<std::string>> messages;

    // dh_hash
    std::map<std::string, std::string> dh_hash;

    // dr_hash 生成的输出
    std::string dr_hash_output;  // 存储 dr_hash 的解析输出

    // dr_hash 类型
    std::string dr_hash_type;  // 存储 "ratchet" 或 "k"

    // 生成 dh_hash 的输出格式
    std::string generate_dh_hash_output(const std::string& l_value) const;

    std::string model_type; //存储modle attack

    std::string server_type;//存储server type

    std::unordered_map<std::string, std::vector<std::string>> process;

    std::vector<std::pair<std::string, std::vector<std::string>>> corr_rule;//存储corr规则

    const std::unordered_set<std::string> known_keywords = {
        "IK_sk_B", "SPK_sk_B", "EK_sk_A", "ctxt", "SK", "skB", "SK_init"
    };
};

class CoreElementParser {
public:
    CoreElement parse(const std::string& filepath);

    // 将 {X} 转换为 ++ get(X) 格式（支持多个变量）
    std::string parseVariableFormat(const std::string& input) {
        std::string result;
        size_t pos = 0;
        
        while (true) {
            size_t start = input.find('{', pos);
            if (start == std::string::npos) break;
            
            size_t end = input.find('}', start);
            if (end == std::string::npos) break;
            
            std::string var = input.substr(start + 1, end - start - 1);
            if (!var.empty()) {
                result += " ++ get(" + var + ")";
            }
            pos = end + 1;
        }
        
        return result;
    }

};

#endif // COREELEMENTPARSER_H
