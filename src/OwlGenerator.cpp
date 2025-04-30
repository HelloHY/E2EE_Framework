#include "OwlGenerator.h"
#include "CoreElementParser.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <unordered_map>

std::string OwlGenerator::genLocalityClient(const std::vector<std::string>& roles) {
    std::stringstream ss;
    for (const auto& role : roles) {
        ss << "locality " << role << "\n";
    }
    ss << "\n";
    return ss.str();
}

std::string OwlGenerator::genClientProcess(const std::vector<std::string>& roles) {
    std::string res;
    if (roles.size() > 0) {
        res += "def " + roles[0] + "_main() @" + roles[0] + " : Unit = call Alice_Accquire_Key()\n";
    }
    if (roles.size() > 1) {
        res += "def " + roles[1] + "_main() @" + roles[1] + " : Unit = call Bob_Publishing_Key()\n";
    }

    return res;
}


std::string OwlGenerator::genLocalityServer(const std::vector<std::string>& roles) {
    std::stringstream ss;
    for (const auto& role : roles) {
        ss << "locality " << role << "\n";
    }
    ss << "\n";
    return ss.str();

}

std::string OwlGenerator::genServerProcess(const std::vector<std::string>& roles) {
    std::stringstream ss;
    for (const auto& role : roles) {
        ss << "def " << role << "_main() @" << role << " : Unit = call " << role << "_distinguish_keys()\n";
    }

    return ss.str();
}

std::string OwlGenerator::genDynamicUserAndCorr(const std::vector<std::string>& roles) {
    std::stringstream ss;
    if (roles.size() >= 2) {
        std::string A = roles[0];
        std::string B = roles[1];
        std::string allRolesList;
        for (size_t i = 0; i < roles.size(); ++i) {
            allRolesList += roles[i];
            if (i != roles.size() - 1) {
                allRolesList += ",";
            }
        }

        ss << "name user" << A << ": nonce @" << allRolesList << "\n";
        ss << "name user" << B << ": nonce @" << allRolesList << "\n";
        ss << "corr [user" << A << "] ==> [user" << B << "]\n";
        ss << "corr [user" << B << "] ==> [user" << A << "]\n";
    }
    ss << "\n";
    return ss.str();
}

std::string OwlGenerator::genKeys(const CoreElement& element) {
    std::stringstream ss;
    for (const auto& [role, keys] : element.dh_keys) {
        for (const auto& k : keys) {
            ss << "name " << k << "_sk_" << role << ":DH @" << role << "\n";
        }
    }
    ss << "\n";
    for (const auto& [role, keys] : element.sig_keys) {
        for (const auto& k : keys) {
            ss << "name " << k << " : sigkey (dhpk(SPK_sk_" << role << ")) @" << role << "\n";
        }
    }
    ss << "\n";
    return ss.str();
}

std::string OwlGenerator::genHashAndCorr(const CoreElement& element) {
    std::stringstream ss;
    
    // 确保有至少两个角色（A和B）
    if (element.clients.size() >= 2) {
        std::string A = element.clients[0];
        std::string B = element.clients[1];

        // 检查并处理 dh_hash
        if (element.dh_hash.find("l") != element.dh_hash.end()) {
            std::string l_value = element.dh_hash.at("l");
            
            // 基础DH组合表达式
            std::string dh_expr = 
                "dh_combine(get(IK_sk_" + B + "),dhpk(get(EK_sk_" + A + "))) ++ " +
                "dh_combine(get(SPK_sk_" + B + "),dhpk(get(IK_sk_" + A + "))) ++ " +
                "dh_combine(get(SPK_sk_" + B + "),dhpk(get(EK_sk_" + A + ")))";
            
            // 动态添加变量（通过CoreElementParser实例）
            CoreElementParser parser;
            if (!l_value.empty()) {
                dh_expr += parser.parseVariableFormat(l_value);
            }

            // 生成OWL代码
            ss << "name l : RO " << dh_expr << " -> enckey Name(ctxt)\n";
            ss << "name l_corr : RO[x] x-> enckey Name(ctxt)\n";
            ss << "    requires x != " << dh_expr << "\n";
            ss << "corr[x] (adv) ==> [l_corr[x;0]]\n\n";
        }
    }
    
    if (element.dr_hash_type == "ratchet") {
        ss << "name ratchet : RO get(SK) -> enckey Name(x)\n";
        ss << "uniqueness_by admit\n\n";
    } 
    else if (element.dr_hash_type == "k") {
        ss << "name k1 : RO get(SK) ++ get(RK) -> nonce  //RK<i+1>\n";
        ss << "uniqueness_by admit\n\n";
        ss << "name k2 : RO get(SK) ++ get(RK) -> enckey Name(x)  //MK<i+1>\n";
        ss << "uniqueness_by admit\n\n";
    }
    
    return ss.str();
}

std::string OwlGenerator::genParams(const CoreElement& element) {
    std::stringstream ss;
    for (const auto& [role, params] : element.parameters) {
        for (const auto& p : params) {
            ss << "name " << p << " : nonce @" << role << "\n";
        }
    }
    ss << "\n";
    return ss.str();
}

std::string OwlGenerator::genMessages(const CoreElement& element) {
    std::stringstream ss;
    
    // 创建角色名称映射表 (全名 -> 缩写)
    std::unordered_map<std::string, std::string> roleMap;
    for (const auto& role : element.clients) {
        roleMap[role] = role; // 默认使用全名
        if (role.size() > 1) { // 如果角色名长度>1，取首字母作为缩写
            roleMap[role] = std::string(1, role[0]);
        }
    }

    for (const auto& [roleFullName, msgs] : element.messages) {
        // 获取当前角色的缩写形式
        std::string role = roleMap[roleFullName];
        
        for (const auto& m : msgs) {
            std::string messageName;
            std::vector<std::string> parameters;

            // 解析消息名和参数
            size_t openParen = m.find('(');
            if (openParen != std::string::npos) {
                messageName = m.substr(0, openParen);
                size_t closeParen = m.find(')', openParen);
                if (closeParen != std::string::npos) {
                    std::string paramStr = m.substr(openParen + 1, closeParen - openParen - 1);
                    std::stringstream paramStream(paramStr);
                    std::string param;
                    while (std::getline(paramStream, param, ',')) {
                        if (!param.empty()) {
                            parameters.push_back(param);
                        }
                    }
                }
            } else {
                messageName = m;
            }

            if (messageName == "AsendMSG") {
                ss << "struct AsendMSG {\n";
                ss << "    _ik_pk_" << role << " : dhpk(IK_sk_" << roleFullName << "),\n";
                ss << "    _ek_pk_" << role << " : dhpk(EK_sk_" << roleFullName << "),\n";
                ss << "    _enc_msg : Data<adv> ||nonce||,\n";
                ss << "    _ad : Data<adv> ||nonce||";
                for (const auto& param : parameters) {
                    ss << ",\n    _" << param << ":Data<adv>";
                }
                ss << "\n}\n\n";
            } 
            else if (messageName == "BuploadPKs") {
                ss << "struct BuploadPKs {\n";
                ss << "    _ik_pk_" << role << " : dhpk(IK_sk_" << roleFullName << "),\n";
                ss << "    _spk_pk_" << role << " : dhpk(SPK_sk_" << roleFullName << "),\n";
                ss << "    _sign_spk_pk_" << role << " : Data<adv> ||signature||";
                for (const auto& param : parameters) {
                    ss << ",\n    _" << param << ":Data<adv>";
                }
                ss << "\n}\n\n";
            } 
            else if (messageName == "A2S_followup_message") {
                std::string targetRole = "B";
                if (roleFullName == "Alice") targetRole = "B";
                else if (roleFullName == "A") targetRole = "B";
                
                ss << "struct A2S_followup_message {\n";
                ss << "    _accept_userID:Name(user" << targetRole << "),\n";
                ss << "    _accept_enc_x:Data<adv>,\n";
                ss << "    //_accept_rootkey: Data<adv>\n}\n\n";
            } 
            else if (messageName == "S2B_followup_message") {
                std::string sourceRole = "A";
                if (roleFullName == "Bob") sourceRole = "A";
                else if (roleFullName == "B") sourceRole = "A";
                
                ss << "struct S2B_followup_message {\n";
                ss << "    _sender_userID:Name(user" << sourceRole << "),\n";
                ss << "    _sender_enc_x:Data<adv>,\n";
                ss << "    //_sender_rootkey: Data<adv>\n}\n\n";
            }
        }
    }
    return ss.str();
}

// 在 OwlGenerator.cpp 中实现
std::string OwlGenerator::generate_dh_hash_output(const std::string& l_value) {
    if (l_value == "{}") {
        return "name l : RO dh_combine(get(IK_sk_B),dhpk(get(EK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(IK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(EK_sk_A))) -> enckey Name(ctxt)\n"
               "name l_corr : RO[x] x-> enckey Name(ctxt)\n"
               "    requires x != dh_combine(get(IK_sk_B),dhpk(get(EK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(IK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(EK_sk_A)))\n"
               "corr[x] (adv) ==> [l_corr[x;0]]";
    } else if (l_value == "{SS}") {
        return "name l : RO dh_combine(get(IK_sk_B),dhpk(get(EK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(IK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(EK_sk_A))) ++ get(SS) -> enckey Name(ctxt)\n"
               "name l_corr : RO[x] x-> enckey Name(ctxt)\n"
               "    requires x != dh_combine(get(IK_sk_B),dhpk(get(EK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(IK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(EK_sk_A))) ++ get(SS)\n"
               "corr[x] (adv) ==> [l_corr[x;0]]";
    }
    return "";
}

void OwlGenerator::generate(const CoreElement& element, const std::string& outputPath) {
    std::ofstream outFile(outputPath);
    if (!outFile) {
        std::cerr << "❌ 无法写入文件: " << outputPath << std::endl;
        return;
    }

    outFile << genLocalityClient(element.clients);
    outFile << genLocalityServer(element.servers);
    outFile << genDynamicUserAndCorr(element.clients);
    outFile << genParams(element);
    outFile << genKeys(element);
    outFile << genHashAndCorr(element);
    outFile << genMessages(element);

    outFile << genClientProcess(element.clients);
    outFile << genServerProcess(element.servers);

    std::cout << "✅ OwlLang 模型已成功写入到 " << outputPath << std::endl;
}
