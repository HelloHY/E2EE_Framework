#include "CoreElementParser.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>

CoreElement CoreElementParser::parse(const std::string& filepath) {
    CoreElement ce;
    std::ifstream file(filepath);
    std::string line, currentSection;

    while (getline(file, line)) {
        if (line.find("//") == 0) {
            currentSection = line.substr(2);
        } else if (!line.empty()) {
            std::stringstream ss(line);
            std::string key, token;
            
            if (currentSection == "roles") {
                std::string firstLine, secondLine;
                getline(ss, firstLine);
                getline(file, secondLine); // 读取第二行

                std::stringstream firstLineSS(firstLine);
                while (firstLineSS >> token) {
                    ce.clients.push_back(token);
                }

                std::stringstream secondLineSS(secondLine);
                while (secondLineSS >> token) {
                    ce.servers.push_back(token);
                }
            } 
            else if (currentSection == "DH keys" || currentSection == "Signature keys" ||
                     currentSection == "parameters" || currentSection == "message") {
                getline(ss, key, ':');
                getline(ss, token);

                // 清理 token 中的括号内容
                std::size_t start_pos = token.find("{");
                std::size_t end_pos = token.find("}");
                if (start_pos != std::string::npos && end_pos != std::string::npos && end_pos > start_pos) {
                    token = token.substr(start_pos + 1, end_pos - start_pos - 1);
                }

                // 分割并存储数据
                std::stringstream vs(token);
                std::string v;
                while (vs >> v) {
                    if (currentSection == "DH keys") ce.dh_keys[key].push_back(v);
                    else if (currentSection == "Signature keys") ce.sig_keys[key].push_back(v);
                    else if (currentSection == "parameters") ce.parameters[key].push_back(v);
                    else ce.messages[key].push_back(v);
                }
            } 
            else if (currentSection == "dh_hash") {
                size_t colon_pos = line.find(':');
                if (colon_pos != std::string::npos) {
                    std::string key = line.substr(0, colon_pos);
                    std::string value = line.substr(colon_pos + 1);
                    ce.dh_hash[key] = value; // 直接存储原始值，如 "l:={SS}"
                }
            }
            else if (currentSection == "dr_hash") {
                // 根据 dr_hash 参数生成不同的输出
                if (line == "k") {
                    ce.dr_hash_output = "name k1 : RO get(SK) ++ get(RK) -> nonce  //RK<i+1>\n"
                                        "uniqueness_by admit\n\n"
                                        "name k2 : RO get(SK) ++ get(RK) -> enckey Name(x)  //MK<i+1>\n"
                                        "uniqueness_by admit";
                    ce.dr_hash_type = "k";
                } else if (line == "ratchet") {
                    ce.dr_hash_output = "name ratchet : RO get(SK) -> enckey Name(x)\n"
                                        "uniqueness_by admit";
                    ce.dr_hash_type = "ratchet";
                }
            }
        }
    }

    // 在输出之前，清理 dr_hash_output 中的所有 '}' 字符
    ce.dr_hash_output.erase(std::remove(ce.dr_hash_output.begin(), ce.dr_hash_output.end(), '}'), ce.dr_hash_output.end());

    return ce;  
}