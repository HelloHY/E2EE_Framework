#include "OwlGenerator.h"
#include "CoreElementParser.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <cctype>
#include <regex>

std::string OwlGenerator::genLocalityClient(const std::vector<std::string> &roles)
{
    std::stringstream ss;
    for (const auto &role : roles)
    {
        ss << "locality " << role << "\n";
    }
    ss << "\n";
    return ss.str();
}

std::string OwlGenerator::genClientMainProcess(const std::vector<std::string> &roles)
{
    std::string res;
    if (roles.size() > 0)
    {
        res += "def " + roles[0] + "_main() @" + roles[0] + " : Unit = call Alice_Accquire_Key()\n";
    }
    if (roles.size() > 1)
    {
        res += "def " + roles[1] + "_main() @" + roles[1] + " : Unit = call Bob_Publishing_Key()\n";
    }

    return res;
}

std::string OwlGenerator::genLocalityServer(const std::vector<std::string> &roles)
{
    std::stringstream ss;
    for (const auto &role : roles)
    {
        ss << "locality " << role << "\n";
    }
    ss << "\n";
    return ss.str();
}

std::string OwlGenerator::genServerMainProcess(const std::vector<std::string> &roles)
{
    std::stringstream ss;
    for (const auto &role : roles)
    {
        ss << "def " << role << "_main() @" << role << " : Unit = call " << role << "_distinguish_keys()\n";
    }

    return ss.str();
}

/**
 * 识别role中的所有角色，生成userclient@cilentname,servername
 * 比如，clients中包含A和B，servers中包含Server
 * 我希望生成
 * name userA : nonce @A,B,Server
 * name userB : nonce @A,B,Server
 * corr [userA] ==> [userB]
    corr [userB] ==> [userA]
 * 但是现在只生成了
 * name userA : nonce @A,B
 * name userB : nonce @A,B
 * corr [userA] ==> [userB]
    corr [userB] ==> [userA]
 *
 * 数据结构：
 *   客户端角色列表：
   std::vector<std::string> clients;
    服务器角色列表：
   std::vector<std::string> servers;
 */
std::string OwlGenerator::genDynamicUserAndCorr(const std::vector<std::string> &clients, const std::vector<std::string> &servers)
{
    std::stringstream ss;

    if (clients.size() >= 2)
    {
        std::string A = clients[0];
        std::string B = clients[1];

        // 合并 clients 和 servers 为 allRolesList
        std::vector<std::string> allRoles = clients;
        allRoles.insert(allRoles.end(), servers.begin(), servers.end());

        // 构造角色列表字符串
        std::string allRolesList;
        for (size_t i = 0; i < allRoles.size(); ++i)
        {
            allRolesList += allRoles[i];
            if (i != allRoles.size() - 1)
            {
                allRolesList += ",";
            }
        }

        // 输出 user 和 corr 语句
        ss << "name user" << A << ": nonce @" << allRolesList << "\n";
        ss << "name user" << B << ": nonce @" << allRolesList << "\n";
        ss << "corr [user" << A << "] ==> [user" << B << "]\n";
        ss << "corr [user" << B << "] ==> [user" << A << "]\n";
    }

    ss << "\n";
    return ss.str();
}

std::string OwlGenerator::genKeys(const CoreElement &element)
{
    std::stringstream ss;

    // 生成 Diffie-Hellman 密钥
    for (const auto &[role, keys] : element.dh_keys)
    {
        for (const auto &k : keys)
        {
            ss << "name " << k << "_sk_" << role << ":DH @" << role << "\n";
        }
    }

    ss << "\n"; // 添加换行，保持输出的清晰

    // 处理签名密钥
    for (const auto &[role, keys] : element.sig_keys)
    {
        for (const auto &k : keys)
        {
            size_t pos1 = k.find('('); // 找到 '('
            size_t pos2 = k.find(')'); // 找到 ')'

            if (pos1 != std::string::npos && pos2 != std::string::npos && pos2 > pos1)
            {
                std::string keyName = k.substr(0, pos1);                      // 密钥名称
                std::string innerParam = k.substr(pos1 + 1, pos2 - pos1 - 1); // 密钥内部参数

                // 处理包含 DH 的情况：移除 "DH"
                if (innerParam.find("DH") != std::string::npos)
                {
                    // 移除 "DH" 部分
                    size_t dhPos = innerParam.find(":DH");
                    if (dhPos != std::string::npos)
                    {
                        innerParam = innerParam.substr(0, dhPos); // 截取去掉 ":DH"
                    }
                }

                // 根据是否包含 "DH" 输出不同格式
                if (k.find("DH") != std::string::npos)
                {
                    ss << "name " << keyName << " : sigkey (dhpk(" << innerParam << ")) @" << role << "\n";
                }
                else
                {
                    ss << "name " << keyName << " : sigkey Name(" << innerParam << ") @" << role << "\n";
                }
            }
            else
            {
                // 没有括号，直接输出
                ss << "name " << k << " : sigkey Name(" << k << ") @" << role << "\n";
            }
        }
    }

    ss << "\n";
    return ss.str();
}

/**将生成hash和生成corr分别写成两个函数
 * genDH_Hash和genDR_Hash
 */

std::string OwlGenerator::genDH_Hash(const CoreElement &element)
{
    std::stringstream ss;

    if (element.clients.size() >= 2)
    {
        std::string A = element.clients[0];
        std::string B = element.clients[1];

        if (element.dh_hash.find("l") != element.dh_hash.end())
        {
            std::string l_value = element.dh_hash.at("l");

            std::string dh_expr =
                "dh_combine(get(IK_sk_" + B + "),dhpk(get(EK_sk_" + A + "))) ++ " +
                "dh_combine(get(SPK_sk_" + B + "),dhpk(get(IK_sk_" + A + "))) ++ " +
                "dh_combine(get(SPK_sk_" + B + "),dhpk(get(EK_sk_" + A + ")))";

            CoreElementParser parser;
            if (!l_value.empty())
            {
                dh_expr += parser.parseVariableFormat(l_value);
            }

            ss << "name l : RO " << dh_expr << " -> enckey Name(ctxt)\n";
            ss << "name l_corr : RO[x] x-> enckey Name(ctxt)\n";
            ss << "    requires x != " << dh_expr << "\n";
            ss << "corr[x] (adv) ==> [l_corr[x;0]]\n\n";
        }
    }

    return ss.str();
}

std::string OwlGenerator::genDR_Hash(const CoreElement &element)
{
    std::stringstream ss;

    if (element.dr_hash_type == "ratchet")
    {
        ss << "name ratchet : RO get(SK) -> enckey Name(x)\n";
        ss << "uniqueness_by admit\n\n";
    }
    else if (element.dr_hash_type == "k")
    {
        ss << "name k1 : RO get(SK) ++ get(RK) -> nonce  //RK<i+1>\n";
        ss << "uniqueness_by admit\n\n";
        ss << "name k2 : RO get(SK) ++ get(RK) -> enckey Name(x)  //MK<i+1>\n";
        ss << "uniqueness_by admit\n\n";
    }

    return ss.str();
}

std::string OwlGenerator::genParams(const CoreElement &element)
{
    // 默认参数必须有name ctxt : nonce @A和name x : nonce @A
    // 其他的参数根据输入生成，如果A和B有共同的参数，那么语法是name x : nonce @A,B

    std::stringstream ss;

    // 输出默认参数
    ss << "name ctxt : nonce @" << element.clients[0] << "\n";
    ss << "name x : nonce @" << element.clients[0] << "\n";
    ss << "name SK_init : enckey Name(ctxt) @" << element.clients[0] << "," << element.clients[1] << "\n";
    ss << "name SK : enckey Name(x) @" << element.clients[0] << "," << element.clients[1] << "\n";

    // 构建参数 -> 所属角色集合 的映射
    std::map<std::string, std::set<std::string>> paramToRoles;

    for (const auto &[role, params] : element.parameters)
    {
        for (const auto &param : params)
        {
            if (param == "ctxt" || param == "x")
                continue; // 跳过默认参数
            paramToRoles[param].insert(role);
        }
    }

    // 输出合并后的参数行
    for (const auto &[param, roles] : paramToRoles)
    {
        ss << "name " << param << " : nonce @";
        bool first = true;
        for (const auto &role : roles)
        {
            if (!first)
                ss << ",";
            ss << role;
            first = false;
        }
        ss << "\n";
    }

    ss << "\n";
    return ss.str();
}

std::string OwlGenerator::genMessages(const CoreElement &element)
{
    std::stringstream ss;

    for (const auto &[role, msgs] : element.messages)
    {
        for (const auto &msg : msgs)
        {
            size_t open = msg.find('(');
            size_t close = msg.find(')');

            if (open == std::string::npos || close == std::string::npos || close <= open)
            {
                std::cerr << "消息格式错误：" << msg << std::endl;
                continue;
            }

            std::string msgName = msg.substr(0, open);
            std::string paramContent = msg.substr(open + 1, close - open - 1);

            ss << "struct " << msgName << " {\n";

            std::vector<std::string> fields;

            // 默认结构
            if (msgName == "AsendMSG")
            {
                fields.push_back("    _ik_pk_" + role + " : dhpk(IK_sk_" + role + ")");
                fields.push_back("    _ek_pk_" + role + " : dhpk(EK_sk_" + role + ")");
                fields.push_back("    _enc_msg : Data<adv> ||nonce||");
                fields.push_back("    _ad : Data<adv> ||nonce||");
            }
            else if (msgName == "BuploadPKs")
            {
                fields.push_back("    _ik_pk_" + role + " : dhpk(IK_sk_" + role + ")");
                fields.push_back("    _spk_pk_" + role + " : dhpk(SPK_sk_" + role + ")");
                fields.push_back("    _sign_spk_pk_" + role + " : Data<adv> ||signature||");
            }
            else if (msgName == "A2S_followup_message")
            {
                fields.push_back("    _accept_userID : Name(userB)");
                fields.push_back("    _accept_enc_x : Data<adv>");
                // fields.push_back("    //_accept_rootkey: Data<adv>");
            }
            else if (msgName == "S2B_followup_message")
            {
                fields.push_back("    _sender_userID : Name(userA)");
                fields.push_back("    _sender_enc_x : Data<adv>");
                // fields.push_back("    //_sender_rootkey: Data<adv>");
            }
            else
            {
                fields.push_back("    // 未定义默认结构的消息类型：" + msgName);
            }

            // 添加扩展参数（使用逗号分隔）
            if (!paramContent.empty())
            {
                std::stringstream paramStream(paramContent);
                std::string pair;
                while (std::getline(paramStream, pair, ','))
                {
                    pair.erase(remove_if(pair.begin(), pair.end(), ::isspace), pair.end());
                    if (pair.empty())
                        continue;

                    size_t colon = pair.find(':');
                    std::string name, type;
                    if (colon != std::string::npos)
                    {
                        name = pair.substr(0, colon);
                        type = pair.substr(colon + 1);
                        fields.push_back("    _" + name + " : Data<adv> ||" + type + "||");
                    }
                    else
                    {
                        name = pair;
                        fields.push_back("    _" + name + " : Data<adv>");
                    }
                }
            }

            // 输出所有字段，最后一个不加逗号
            for (size_t i = 0; i < fields.size(); ++i)
            {
                ss << fields[i];
                if (i != fields.size() - 1)
                    ss << ",";
                ss << "\n";
            }

            ss << "}\n\n";
        }
    }

    return ss.str();
}

// 工具函数：全局替换
void replaceAll(std::string &str, const std::string &from, const std::string &to)
{
    if (from.empty())
        return;
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos)
    {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
}

// 首字母大写（x -> X）
std::string capitalizeFirstLetter(const std::string &s)
{
    if (s.empty())
        return s;
    std::string result = s;
    result[0] = toupper(result[0]);
    return result;
}

// input_func: 将 input(x) 转为 let X = _x(Source) in
std::string input_func(const std::string &inputExpr, const std::string &sourceName)
{
    if (inputExpr.find("input(") == 0 && inputExpr.back() == ')')
    {
        std::string varName = inputExpr.substr(6, inputExpr.size() - 7); // 提取 x
        std::string capitalizedVar = capitalizeFirstLetter(varName);
        return "let " + capitalizedVar + " = _" + varName + "(" + sourceName + ") in";
    }
    return "";
}

std::string trim(const std::string &s)
{ // 去掉空格
    auto start = s.begin();
    while (start != s.end() && std::isspace(*start))
        ++start;

    auto end = s.end();
    do
    {
        --end;
    } while (std::distance(start, end) > 0 && std::isspace(*end));

    return std::string(start, end + 1);
}

std::string OwlGenerator::genClientProcess(const CoreElement &element)
{
    std::stringstream ss;

    if (!element.model_type.empty())
    {
        std::filesystem::path filePath = std::filesystem::current_path() / "src" / "AttackModel" / (element.model_type + ".txt");
        // std::filesystem::path filePath = std::filesystem::current_path() / "src" / "AttackModel" / "test.txt";
        std::ifstream attackFile(filePath);

        if (!attackFile)
        {
            std::cerr << "无法打开模型文件：" << filePath << std::endl;
            return "";
        }

        std::string line;
        std::string vrfyCache;
        while (std::getline(attackFile, line)) // 全局修改的内容
        {

            ss << line << "\n";

            // dr_hash op
            if (line.find("//dr_hash op") != std::string::npos)
            {
                if (element.dr_hash_type == "ratchet")
                {
                    ss << "    let SK = hash<ratchet;0>(get(SK)) in\n";
                }
                else if (element.dr_hash_type == "k")
                {
                    ss << "     let SK = hash<k2;0>(get(SK),get(RK)) in\n";
                    ss << "     let RK = hash<k1;0>(get(SK),get(RK)) in\n";
                }
            }

            // dr_hash check
            if (line.find("//dr_hash check") != std::string::npos)
            {
                if (element.dr_hash_type == "ratchet")
                {
                    ss << "     let res : if sec(ratchet) then Name(x) else Data<adv> = x in\n";
                }
                else if (element.dr_hash_type == "k")
                {
                    ss << "     let res : if sec(k1)  /\\ sec(k2) then Name(x) else Data<adv> = x in\n";
                }
            }

            // dh_hash op
            if (line.find("//dh_hash op") != std::string::npos)
            {
                ss << "       let SK = hash<l;0>(S) in\n";
            }

            // Alice calculate shared secret
            if (line.find("//Alice calculate shared secret") != std::string::npos)
            {
                auto it = element.dh_hash.find("l");

                // 读取下一行（原始的 let S = ...）
                std::string nextLine;
                std::getline(attackFile, nextLine); // 跳过原始的 let S 行

                if (it != element.dh_hash.end())
                {
                    std::string rawValue = it->second;
                    size_t braceOpen = rawValue.find("{");
                    size_t braceClose = rawValue.find("}");

                    std::string fieldContent;
                    if (braceOpen != std::string::npos && braceClose != std::string::npos && braceClose > braceOpen)
                    {
                        fieldContent = rawValue.substr(braceOpen + 1, braceClose - braceOpen - 1);
                    }

                    if (fieldContent.empty())
                    {
                        // 空字段，原样保留原始 let S 行
                        ss << line << "\n";
                        ss << nextLine << "\n";
                    }
                    else
                    {
                        // 解析字段生成 concat 表达式
                        std::stringstream ssFields(fieldContent);
                        std::string token;
                        std::vector<std::string> fields;

                        while (std::getline(ssFields, token, ','))
                        {
                            token.erase(remove_if(token.begin(), token.end(), ::isspace), token.end());
                            if (!token.empty())
                                fields.push_back("get(" + token + ")");
                        }

                        // 构建嵌套结构
                        std::string tailConcat;
                        for (auto it = fields.rbegin(); it != fields.rend(); ++it)
                        {
                            if (tailConcat.empty())
                                tailConcat = *it;
                            else
                                tailConcat = "concat(" + *it + "," + tailConcat + ")";
                        }

                        // 拼接生成整行
                        // ss << line << "\n"; // 仍保留注释行
                        ss << "                let S = concat(dh_combine(get(IK_sk_A),bobs_pk), "
                           << "concat(dh_combine(get(EK_sk_A),IK_pk_B),"
                           << "concat(dh_combine(get(EK_sk_A),bobs_pk),"
                           << tailConcat << "))) in\n";
                    }
                }
                else
                {
                    // 没有字段，默认行为：原样输出
                    ss << line << "\n";
                    std::getline(attackFile, nextLine);
                    ss << nextLine << "\n";
                }
            }
            // Bob calculate shared secret
            if (line.find("//Bob calculate shared secret") != std::string::npos)
            {
                auto it = element.dh_hash.find("l");

                // 读取下一行（原始的 let S = ...）
                std::string nextLine;
                std::getline(attackFile, nextLine); // 跳过原始的 let S 行

                if (it != element.dh_hash.end())
                {
                    std::string rawValue = it->second;
                    size_t braceOpen = rawValue.find("{");
                    size_t braceClose = rawValue.find("}");

                    std::string fieldContent;
                    if (braceOpen != std::string::npos && braceClose != std::string::npos && braceClose > braceOpen)
                    {
                        fieldContent = rawValue.substr(braceOpen + 1, braceClose - braceOpen - 1);
                    }

                    if (fieldContent.empty())
                    {
                        // 空字段，原样保留原始 let S 行
                        ss << line << "\n";
                        ss << nextLine << "\n";
                    }
                    else
                    {
                        // 解析字段生成 concat 表达式
                        std::stringstream ssFields(fieldContent);
                        std::string token;
                        std::vector<std::string> fields;

                        while (std::getline(ssFields, token, ','))
                        {
                            token.erase(remove_if(token.begin(), token.end(), ::isspace), token.end());
                            if (!token.empty())
                                fields.push_back("get(" + token + ")");
                        }

                        // 构建嵌套结构
                        std::string tailConcat;
                        for (auto it = fields.rbegin(); it != fields.rend(); ++it)
                        {
                            if (tailConcat.empty())
                                tailConcat = *it;
                            else
                                tailConcat = "concat(" + *it + "," + tailConcat + ")";
                        }

                        // 拼接生成整行
                        // ss << line << "\n"; // 仍保留注释行
                        ss << "             let S = concat(dh_combine(get(IK_sk_B),EK_pk_A), "
                           << "concat(dh_combine(get(SPK_sk_B),IK_pk_A),"
                           << "concat(dh_combine(get(SPK_sk_B),EK_pk_A),"
                           << tailConcat << "))) in\n";
                    }
                }
                else
                {
                    // 没有字段，默认行为：原样输出
                    ss << line << "\n";
                    std::getline(attackFile, nextLine);
                    ss << nextLine << "\n";
                }
            }
            // pcase shared secret
            if (line.find("//pcase shared secret") != std::string::npos)
            {
                auto it = element.dh_hash.find("l");

                // 读取下一行（原始的 pcase 行）
                std::string nextLine;
                std::getline(attackFile, nextLine);

                // 默认 base 结构
                std::string base =
                    "    pcase (S == dh_combine(get(IK_sk_A),dhpk(get(SPK_sk_B)))"
                    " ++ dh_combine(get(EK_sk_A),dhpk(get(IK_sk_B)))"
                    " ++ dh_combine(get(EK_sk_A),dhpk(get(SPK_sk_B)))";

                if (it != element.dh_hash.end())
                {
                    std::string rawValue = it->second;
                    size_t braceOpen = rawValue.find("{");
                    size_t braceClose = rawValue.find("}");

                    std::string fieldContent;
                    if (braceOpen != std::string::npos && braceClose != std::string::npos && braceClose > braceOpen)
                    {
                        fieldContent = rawValue.substr(braceOpen + 1, braceClose - braceOpen - 1);
                    }

                    // 追加字段拼接
                    if (!fieldContent.empty())
                    {
                        std::stringstream ssFields(fieldContent);
                        std::string token;
                        while (std::getline(ssFields, token, ','))
                        {
                            token.erase(remove_if(token.begin(), token.end(), ::isspace), token.end());
                            if (!token.empty())
                                base += " ++ get(" + token + ")";
                        }
                    }
                }

                base += ") in"; // 补全行尾

                // 输出更新内容
                ss << base << "\n"; // 新生成的 pcase 行
            }
            // requires Bob_Publishing_Key corr
            /**
             * 识别//attack model的内容，如果是model1或者model2，那么输出requires corr(IK_sk_B) /\ corr(SPK_sk_B)
             * modle attack的数据结果：std::string model_type; //存储modle attack
             */
            if (line.find("//requires Bob_Publishing_Key corr") != std::string::npos)
            {
                if( (element.model_type == "model3" && element.server_type == "server1") || (element.model_type == "model1" && element.server_type == "server1"))
                {
                    ss << "requires sec(IK_sk_B) /\\ sec(SPK_sk_B) \n";
                }
                else if( (element.model_type == "model3" && element.server_type == "server2") || (element.model_type == "model1" && element.server_type == "server2"))
                {
                    ss << "requires corr(IK_sk_B) /\\ corr(SPK_sk_B) \n";
                }
                else 
                {
                    ss << "requires corr(IK_sk_B) /\\ corr(SPK_sk_B)"; // 默认输出

                    auto it = element.process.find("Bob_Publishing_Key");
                    if (it != element.process.end() && !it->second.empty())
                    {
                        for (const std::string &expr : it->second)
                        {
                            std::string trimmedExpr = expr;
                            trimmedExpr.erase(remove_if(trimmedExpr.begin(), trimmedExpr.end(), ::isspace), trimmedExpr.end());

                            std::regex corrPattern(R"(corr\((\w+)\))");
                            std::smatch match;
                            if (std::regex_search(trimmedExpr, match, corrPattern))
                            {
                                std::string x = match[1];
                                ss << " /\\ corr(" << x << ")";
                            }
                        }
                    }

                    ss << "\n"; // 最后换行
                }
            }

            // requires Bob_receive_key corr
            /**
             * 识别//attack model的内容，如果是model1或者model2，那么不输出，否则输出“//TODO”
             * modle attack的数据结果：std::string model_type; //存储modle attack
             */
            if (line.find("//requires Bob_receive_key corr") != std::string::npos)
            {
                if (element.model_type != "model1" && element.model_type != "model2")
                {
                    // TODO
                }
                else
                {
                    auto it = element.process.find("Bob_receive_key");
                    if (it != element.process.end() && !it->second.empty())
                    {
                        bool printed = false;
                        for (const std::string &expr : it->second)
                        {
                            std::string trimmedExpr = expr;
                            trimmedExpr.erase(remove_if(trimmedExpr.begin(), trimmedExpr.end(), ::isspace), trimmedExpr.end());

                            std::regex corrPattern(R"(corr\((\w+)\))");
                            std::smatch match;
                            if (std::regex_search(trimmedExpr, match, corrPattern))
                            {
                                if (!printed)
                                {
                                    ss << "requires corr(RK_sk_B)";
                                    printed = true;
                                }
                                std::string x = match[1];
                                ss << " /\\ corr(" << x << ")";
                            }
                        }

                        if (printed)
                        {
                            ss << "\n";
                        }
                    }
                }
            }

            // requires Alice_Accquire_Key corr
            /**
             * 识别//attack model的内容，如果是model2，那么输出requires sec(IK_sk_A) /\ sec(EK_sk_A) /\ sec(skB)
             * 否则与现有的逻辑一致
             * modle attack的数据结果：std::string model_type; //存储modle attack
             */
            if (line.find("//requires Alice_Accquire_Key corr") != std::string::npos)
            {
                if (element.model_type == "model2" || element.model_type == "model3")
                {
                    // 如果是 model2，固定输出 sec(...)
                    ss << "requires sec(IK_sk_A) /\\ sec(EK_sk_A) /\\ sec(SK_init)\n";
                }
                else
                {
                    ss << "requires corr(skB)"; // 默认输出

                    auto it = element.process.find("Alice_Accquire_Key");
                    if (it != element.process.end() && !it->second.empty())
                    {
                        for (const std::string &expr : it->second)
                        {
                            std::string trimmedExpr = expr;
                            trimmedExpr.erase(remove_if(trimmedExpr.begin(), trimmedExpr.end(), ::isspace), trimmedExpr.end());

                            std::regex corrPattern(R"(corr\((\w+)\))");
                            std::smatch match;
                            if (std::regex_search(trimmedExpr, match, corrPattern))
                            {
                                std::string x = match[1];
                                ss << " /\\ corr(" << x << ")";
                            }
                        }
                    }

                    ss << "\n";
                }
            }

            // requires Alice_send_followup_message corr
            if (line.find("//requires Alice_send_followup_message corr") != std::string::npos)
            {
                if (element.model_type == "model2")
                {
                    // 如果是 model1或2，固定输出
                    ss << "requires corr(SK)\n";
                }
                else if (element.model_type == "model3") // no robust
                {
                    ss << "requires corr(userB) /\\ corr(userA)\n";
                }
            }
            // BuploadPKs msg
            if (line.find("//BuploadPKs msg") != std::string::npos)
            {
                auto it = element.process.find("Bob_Publishing_Key");

                if (it != element.process.end() && !it->second.empty())
                {
                    for (const std::string &expr : it->second)
                    {
                        std::string trimmedExpr = expr;
                        trimmedExpr.erase(remove_if(trimmedExpr.begin(), trimmedExpr.end(), ::isspace), trimmedExpr.end());

                        // 检查是否包含 corr(x) 形式，如果是则跳过该表达式
                        if (trimmedExpr.find("corr(") == std::string::npos && !trimmedExpr.empty())
                        {
                            ss << "let " << trimmedExpr << " in\n";
                        }
                    }
                }
            }

            // input InitialMessageFromServer
            if (line.find("//input InitialMessageFromServer msg") != std::string::npos)
            {
                auto it = element.process.find("Bob_receive_key");
                if (it != element.process.end() && !it->second.empty())
                {
                    const std::vector<std::string> &ops = it->second;

                    for (const std::string &op : ops)
                    {
                        std::string trimmedOp = trim(op); // 去掉前后空格

                        // 忽略包含 vrfy 的语句
                        if (trimmedOp.find("vrfy") != std::string::npos)
                            continue;

                        // 如果包含 pcase，直接输出 pcase ... in
                        if (trimmedOp.find("pcase") != std::string::npos)
                        {
                            ss << trimmedOp << " in\n";
                            continue;
                        }

                        if (trimmedOp.find("input(") == 0 && trimmedOp.back() == ')')
                        {
                            // 是 input(...) 表达式
                            ss << input_func(trimmedOp, "InitialMessageFromServer") << "\n";
                        }
                        else
                        {
                            // 不是 input(...)，作为 let 表达式输出
                            ss << "let " << trimmedOp << " in\n";
                        }
                    }
                }
            }
            // input BPKsFromServer
            if (line.find("//input BPKsFromServer msg") != std::string::npos)
            {
                auto it = element.process.find("Alice_Accquire_Key");
                if (it != element.process.end() && !it->second.empty())
                {
                    const std::vector<std::string> &ops = it->second;

                    for (const std::string &op : ops)
                    {
                        std::string trimmedOp = trim(op); // trim() 去掉前后空格的函数

                        // 忽略包含 vrfy 的语句
                        if (trimmedOp.find("vrfy") != std::string::npos)
                            continue;

                        if (trimmedOp.find("input(") == 0 && trimmedOp.back() == ')')
                        {
                            // 是 input(...) 表达式
                            ss << input_func(trimmedOp, "BPKsFromServer") << "\n";
                        }
                        else
                        {
                            // 不是 input(...)，直接作为 let 表达式输出
                            ss << "let " << trimmedOp << " in\n";
                        }
                    }
                }
            }
            // output BuploadPKs msg
            if (line.find("//output BuploadPKs msg") != std::string::npos)
            {
                auto it = element.messages.find("B");
                if (it != element.messages.end())
                {
                    for (const std::string &msg : it->second)
                    {
                        if (msg.find("BuploadPKs(") != std::string::npos)
                        {
                            size_t open = msg.find('(');
                            size_t close = msg.find(')');
                            if (open != std::string::npos && close != std::string::npos && close > open)
                            {
                                std::string paramContent = msg.substr(open + 1, close - open - 1);
                                std::stringstream paramStream(paramContent);
                                std::string param;
                                std::vector<std::string> extraParams;

                                while (std::getline(paramStream, param, ','))
                                {
                                    param = trim(param); // 去空格
                                    if (!param.empty())
                                    {
                                        // 如果是 name:type，则提取 name
                                        size_t colon = param.find(':');
                                        std::string nameOnly = (colon != std::string::npos) ? param.substr(0, colon) : param;
                                        extraParams.push_back(nameOnly);
                                    }
                                }

                                // 构建输出语句
                                std::string outputLine = "let _ = output BuploadPKs(IK_pk_B,SPK_pk_B,sign_spk_pk_B";

                                for (const auto &p : extraParams)
                                {
                                    outputLine += "," + p;
                                }

                                outputLine += ") to endpoint(";
                                if (element.servers.size() > 1)
                                    outputLine += element.servers[1]; // 改为第二个服务器
                                else
                                    outputLine += "Server"; // 保持默认 Server

                                outputLine += ") in";

                                ss << outputLine << "\n";
                                break; // 只处理第一个 BuploadPKs
                            }
                        }
                    }
                }
            }
            // Alice_send_followup_message msg
            if (line.find("//Alice_send_followup_message msg") != std::string::npos)
            {
                auto it = element.process.find("Alice_send_followup_message");

                if (it != element.process.end() && !it->second.empty())
                {
                    for (const std::string &expr : it->second)
                    {
                        std::string trimmedExpr = expr;
                        trimmedExpr.erase(remove_if(trimmedExpr.begin(), trimmedExpr.end(), ::isspace), trimmedExpr.end());

                        // 如果不是 corr(...) 且不为空，就输出
                        if (trimmedExpr.find("corr(") == std::string::npos && !trimmedExpr.empty())
                        {
                            ss << "   let " << expr << " in\n"; // ⚠️ 使用原始 expr 保留空格
                        }
                    }
                }
                else
                {
                    std::cerr << "[Debug] 未找到 Alice_send_followup_message 或字段为空\n";
                }
            }
            // output Alice_send_followup_message msg
            if (line.find("//output Alice_send_followup_message msg") != std::string::npos)
            {
                auto it = element.messages.find("Server");
                if (it != element.messages.end())
                {
                    for (const std::string &msg : it->second)
                    {
                        if (msg.find("A2S_followup_message(") != std::string::npos)
                        {
                            size_t open = msg.find('(');
                            size_t close = msg.find(')');
                            if (open != std::string::npos && close != std::string::npos && close > open)
                            {
                                std::string paramContent = msg.substr(open + 1, close - open - 1);
                                std::stringstream paramStream(paramContent);
                                std::string param;
                                std::vector<std::string> extraParams;

                                while (std::getline(paramStream, param, ','))
                                {
                                    param = trim(param); // 去空格
                                    if (!param.empty())
                                    {
                                        // 如果是 name:type，则提取 name
                                        size_t colon = param.find(':');
                                        std::string nameOnly = (colon != std::string::npos) ? param.substr(0, colon) : param;
                                        extraParams.push_back(nameOnly);
                                    }
                                }

                                // 构建输出语句
                                std::string outputLine = "     let _ = output A2S_followup_message(accept_userID , accept_enc_x";

                                for (const auto &p : extraParams)
                                {
                                    outputLine += "," + p;
                                }

                                outputLine += ") to endpoint(";
                                if (element.servers.size() > 1)
                                    outputLine += element.servers[0]; // 改为第二个服务器
                                else
                                    outputLine += "Server"; // 保持默认 Server

                                outputLine += ") in";

                                ss << outputLine << "\n";
                                break; // 只处理第一个 BuploadPKs
                            }
                        }
                    }
                }
            }
            // input S2B_followup_message_fromB msg
            if (line.find("input S2B_followup_message_fromB msg") != std::string::npos)
            {
                auto it = element.process.find("Bob_receive_followup_message");
                if (it != element.process.end() && !it->second.empty())
                {
                    const std::vector<std::string> &ops = it->second;

                    for (const std::string &op : ops)
                    {
                        std::string trimmedOp = trim(op); // 去掉前后空格

                        // 忽略包含 vrfy 的语句
                        if (trimmedOp.find("vrfy") != std::string::npos)
                            continue;

                        // 如果包含 pcase，直接输出 pcase ... in
                        if (trimmedOp.find("pcase") != std::string::npos)
                        {
                            ss << trimmedOp << " in\n";
                            continue;
                        }

                        if (trimmedOp.find("input(") == 0 && trimmedOp.back() == ')')
                        {
                            // 是 input(...) 表达式
                            ss << input_func(trimmedOp, "S2B_followup_message_fromB") << "\n";
                        }
                        else
                        {
                            // 不是 input(...)，作为 let 表达式输出
                            ss << "let " << trimmedOp << " in\n";
                        }
                    }
                }
            }
            // get dr_keys
            if (line.find("//get dr_keys") != std::string::npos)
            {
                if (element.dr_hash_type == "k")
                {
                    ss << "    let SK = hash<k2;0>(get(SK),get(RK)) in\n";
                    ss << "    let RK = hash<k1;0>(get(SK),get(RK)) in\n";
                }
                else if (element.dr_hash_type == "ratchet")
                {
                    ss << "    let SK = hash<ratchet;0>(get(SK)) in\n";
                }
            }

            // other ops
            if (line.find("//other ops") != std::string::npos)
            {
                auto it = element.process.find("Alice_Accquire_Key");
                if (it != element.process.end())
                {
                    std::string combined;
                    for (const auto &part : it->second)
                    {
                        combined += part + ";";
                    }

                    std::smatch match;

                    // 新正则：匹配 vrfy(alias:vk(sk),sig,msg)=val
                    std::regex vrfyPattern(R"(vrfy\s*\(\s*([a-zA-Z0-9_]+)\s*:\s*vk\s*\(\s*([a-zA-Z0-9_]+)\s*\)\s*,\s*([a-zA-Z0-9_]+)\s*,\s*([a-zA-Z0-9_]+)\s*\)\s*=\s*([a-zA-Z0-9_]+))");

                    if (std::regex_search(combined, match, vrfyPattern))
                    {
                        std::string alias = match[1]; // 解密公钥别名，如 vkB_POSPK
                        std::string sk = match[2];    // 解密私钥，如 skB_PQSPK
                        std::string sig = match[3];   // 签名，如 sign_spk_pk_B_PQSPK
                        std::string msg = match[4];   // 消息，如 pqspk_pk_B
                        std::string val = match[5];   // 期望值，如 bobs_pqspk

                        // 插入第一部分：在 //other ops 下方
                        ss << "             corr_case " << sk << " in\n";
                        ss << "             case vrfy(" << alias << "," << sig << "," << msg << ") {\n";
                        ss << "             | Some " << val << " =>\n";

                        // 第二部分缓存，稍后插入
                        vrfyCache = "    | None => ()\n";
                    }
                    else
                    {
                        std::cerr << "Error: 未找到格式正确的 vrfy(alias:vk(sk),sig,msg)=val 表达式\n";
                    }
                }
            }
            // other ops end
            if (line.find("//end other ops") != std::string::npos)
            {
                if (!vrfyCache.empty())
                {
                    ss << "         " << vrfyCache;
                    ss << "         }\n"; // 加上闭合花括号和注释
                    vrfyCache.clear();
                }
            }
            // output AsendMSG msg
            if (line.find("//output AsendMSG msg") != std::string::npos)
            {
                auto it = element.messages.find("A");
                if (it != element.messages.end())
                {
                    for (const std::string &msg : it->second)
                    {
                        if (msg.find("AsendMSG(") != std::string::npos)
                        {
                            size_t open = msg.find('(');
                            size_t close = msg.find(')');
                            if (open != std::string::npos && close != std::string::npos && close > open)
                            {
                                std::string paramContent = msg.substr(open + 1, close - open - 1);
                                std::stringstream paramStream(paramContent);
                                std::string param;
                                std::vector<std::string> extraParams;

                                while (std::getline(paramStream, param, ','))
                                {
                                    param = trim(param); // 去空格
                                    if (!param.empty())
                                    {
                                        // 如果是 name:type，则提取 name
                                        size_t colon = param.find(':');
                                        std::string nameOnly = (colon != std::string::npos) ? param.substr(0, colon) : param;
                                        extraParams.push_back(nameOnly);
                                    }
                                }

                                // 构建输出语句
                                std::string outputLine = "let _ = output AsendMSG(dhpk(get(IK_sk_A)),dhpk(get(EK_sk_A)),_enc_msg,AD";

                                for (const auto &p : extraParams)
                                {
                                    outputLine += "," + p;
                                }

                                outputLine += ") to endpoint(";
                                if (!element.servers.empty())
                                    outputLine += element.servers[0]; // 使用第一个服务器名
                                else
                                    outputLine += "Server"; // fallback 保底情况

                                outputLine += ") in";

                                ss << outputLine << "\n";
                                break; // 只处理第一个 AsendMSG
                            }
                        }
                    }
                }
            }
        }
        attackFile.close();
    }
    return ss.str();
}
// 服务器
/*
void OwlGenerator::ProcessServerName(const CoreElement &element)
{
    std::filesystem::path outputPath = std::filesystem::current_path() / "output.owl";
    std::ifstream inFile(outputPath);
    if (!inFile)
    {
        std::cerr << "无法打开 output.owl 文件进行后处理。" << std::endl;
        return;
    }

    std::stringstream buffer;
    buffer << inFile.rdbuf();
    std::string content = buffer.str();
    inFile.close();

    std::stringstream result;
    std::istringstream stream(content);
    std::string line;
    bool inAServerBlock = false;
    bool inBServerBlock = false;
    bool modifyNextLineAfterAServerMarker = false;
    bool modifyNextLineAfterBServerMarker = false;

    while (std::getline(stream, line))
    {
        // 检查是否进入 AServer 块
        if (line.find("// ==== Injected for server: AServer") != std::string::npos)
        {
            std::cout << ">>> 进入 AServer 区块" << std::endl;
            inAServerBlock = true;
            inBServerBlock = false;
        }
        // 检查是否进入 BServer 块
        else if (line.find("// ==== Injected for server: BServer") != std::string::npos)
        {
            std::cout << ">>> 进入 BServer 区块" << std::endl;
            inAServerBlock = false;
            inBServerBlock = true;
        }

        // 查找目标注释行，准备修改其下一行
        if (inAServerBlock && line.find("//AServer transfer initial message") != std::string::npos)
        {
            std::cout << "找到 //AServer transfer initial message" << std::endl;
            modifyNextLineAfterAServerMarker = true;
        }
        else if (inBServerBlock && line.find("//BServer distinguish keys") != std::string::npos)
        {
            std::cout << "找到 //BServer distinguish keys" << std::endl;
            modifyNextLineAfterBServerMarker = true;
        }
        else if (modifyNextLineAfterAServerMarker)
        {
            std::cout << "[AServer] 替换前: " << line << std::endl;
            replaceAll(line, "endpoint(B)", "endpoint(" + element.servers[1] + ")");
            std::cout << "[AServer] 替换后: " << line << std::endl;
            modifyNextLineAfterAServerMarker = false;
        }
        else if (modifyNextLineAfterBServerMarker)
        {
            std::cout << "[BServer] 替换前: " << line << std::endl;
            replaceAll(line, "endpoint(A)", "endpoint(" + element.servers[0] + ")");
            std::cout << "[BServer] 替换后: " << line << std::endl;
            modifyNextLineAfterBServerMarker = false;
        }

        result << line << "\n";
    }


    std::ofstream outFile(outputPath);
    if (!outFile)
    {
        std::cerr << "无法写入 output.owl 文件（覆盖写）" << std::endl;
        return;
    }

    outFile << result.str();
    outFile.close();
}
    */

/**
 * 找到//requires  A2S_followup_messaage_fromA corr，在下一行输出
 * requires corr(userA) /\ corr(userB)
 */
std::string OwlGenerator::genServerProcess(const CoreElement &element)
{
    std::filesystem::path inputPath = std::filesystem::current_path() / "src" / "AttackModel" / (element.server_type + ".txt");
    std::ifstream serverFile(inputPath);

    if (!serverFile)
    {
        std::cerr << "无法打开 server 模型文件：" << inputPath << std::endl;
        return "";
    }

    std::stringstream buffer;
    buffer << serverFile.rdbuf();
    std::string templateContent = buffer.str();
    serverFile.close();

    std::string finalContent;

    for (const auto &serverName : element.servers)
    {
        std::string customizedContent = templateContent;
        size_t pos = 0;
        while ((pos = customizedContent.find("Server", pos)) != std::string::npos)
        {
            customizedContent.replace(pos, 6, serverName);
            pos += serverName.length();
        }

        finalContent += "// ==== Injected for server: " + serverName + " ====\n";
        finalContent += customizedContent + "\n";
    }

    // 替换 AServer 的 transfer initial message 部分
    size_t a_marker = finalContent.find("//AServer transfer initial message");
    if (a_marker != std::string::npos)
    {
        size_t line_start = finalContent.find('\n', a_marker);
        size_t line_end = finalContent.find('\n', line_start + 1);
        if (line_start != std::string::npos && line_end != std::string::npos)
        {
            std::string line = finalContent.substr(line_start + 1, line_end - line_start - 1);
            std::string replaced = line;
            replaceAll(replaced, "endpoint(B)", "endpoint(" + element.servers[1] + ")");
            finalContent.replace(line_start + 1, line.length(), replaced);
        }
    }

    // 替换 BServer 的 distinguish keys 部分
    size_t b_marker = finalContent.find("//BServer distinguish keys");
    if (b_marker != std::string::npos)
    {
        size_t line_start = finalContent.find('\n', b_marker);
        size_t line_end = finalContent.find('\n', line_start + 1);
        if (line_start != std::string::npos && line_end != std::string::npos)
        {
            std::string line = finalContent.substr(line_start + 1, line_end - line_start - 1);
            std::string replaced = line;
            replaceAll(replaced, "endpoint(A)", "endpoint(" + element.servers[0] + ")");
            finalContent.replace(line_start + 1, line.length(), replaced);
        }
    }

    // 插入 Server transfer followup message 行后的语句
    size_t transfer_marker = finalContent.find("//Server transfer followup message");
    if (transfer_marker != std::string::npos)
    {
        size_t line_start = finalContent.find('\n', transfer_marker);
        if (line_start != std::string::npos)
        {
            std::string injectLine = "let _sender_rootkey = _accept_rootkey(A2S_followup_messaage_fromA) in\n";
            finalContent.insert(line_start + 1, injectLine);
        }
    }

    // 插入 requires corr(...) 动态角色名
    size_t requires_marker = finalContent.find("//requires  A2S_followup_messaage_fromA corr");
    if (requires_marker != std::string::npos && element.clients.size() >= 2)
    {
        std::string clientA = element.clients[0];
        std::string clientB = element.clients[1];
        size_t line_start = finalContent.find('\n', requires_marker);
        if (line_start != std::string::npos)
        {
            std::string injectLine = "requires corr(user" + clientA + ") /\\ corr(user" + clientB + ")\n";
            finalContent.insert(line_start + 1, injectLine);
        }
    }

    return finalContent;
}

// 在 OwlGenerator.cpp 中实现
std::string OwlGenerator::generate_dh_hash_output(const std::string &l_value)
{
    if (l_value == "{}")
    {
        return "name l : RO dh_combine(get(IK_sk_B),dhpk(get(EK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(IK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(EK_sk_A))) -> enckey Name(ctxt)\n"
               "name l_corr : RO[x] x-> enckey Name(ctxt)\n"
               "    requires x != dh_combine(get(IK_sk_B),dhpk(get(EK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(IK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(EK_sk_A)))\n"
               "corr[x] (adv) ==> [l_corr[x;0]]";
    }
    else if (l_value == "{SS}")
    {
        return "name l : RO dh_combine(get(IK_sk_B),dhpk(get(EK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(IK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(EK_sk_A))) ++ get(SS) -> enckey Name(ctxt)\n"
               "name l_corr : RO[x] x-> enckey Name(ctxt)\n"
               "    requires x != dh_combine(get(IK_sk_B),dhpk(get(EK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(IK_sk_A))) ++ dh_combine(get(SPK_sk_B),dhpk(get(EK_sk_A))) ++ get(SS)\n"
               "corr[x] (adv) ==> [l_corr[x;0]]";
    }
    return "";
}

std::string OwlGenerator::genCorr(const CoreElement &element)
{
    std::vector<std::string> lines;

    // 默认规则
    std::vector<std::string> defaultCorr = {
        "corr [IK_sk_B] ==> [SPK_sk_B]",
        "corr [skB] ==> [IK_sk_B]",
        "corr [skB] ==> [SPK_sk_B]",
        "corr [skB] ==> [IK_sk_A]",
        "corr [skB] ==> [EK_sk_A]",
        "corr [IK_sk_B] ==> [ctxt]",
        "corr [SPK_sk_B] ==> [ctxt]",
        "corr [IK_sk_A] ==> [ctxt]",
        "corr [EK_sk_A] ==> [ctxt]",
        "corr [ctxt] ==> [IK_sk_B]",
        "corr [ctxt] ==> [SPK_sk_B]",
        "corr [ctxt] ==> [EK_sk_A]",
        "corr [ctxt] ==> [IK_sk_A]",
    };

    // 添加默认规则
    for (const auto &line : defaultCorr)
    {
        lines.push_back(line);
    }

    // 添加 corr_rule 中的规则
    for (const auto &[lhs, rhs_list] : element.corr_rule)
    {
        for (const auto &rhs : rhs_list)
        {
            std::string line = "corr [" + lhs + "] ==> [" + rhs + "]";
            lines.push_back(line);
        }
    }

    // 拼接输出
    std::stringstream ss;
    for (const auto &line : lines)
        ss << line << "\n";

    ss << "\n";
    return ss.str();
}

std::string OwlGenerator::genModel4AndServer3(const CoreElement &element)
{
    std::ostringstream finalOutput;

    // 读取并处理 model4.txt
    std::filesystem::path modelPath = std::filesystem::current_path() / "src" / "AttackModel" / (element.model_type + ".txt");
    std::ifstream modelFile(modelPath);
    if (!modelFile)
    {
        std::cerr << "❌ 无法打开 model 文件: " << modelPath << std::endl;
        return "";
    }

    std::ostringstream modelProcessed;
    std::string line;
    size_t serverCount = element.servers.size();

    while (std::getline(modelFile, line))
    {
        modelProcessed << line << "\n";

        if (line.find("//server locality") != std::string::npos)
        {
            for (const auto &s : element.servers)
            {
                modelProcessed << "locality " << s << "\n";
            }
        }

        if (line.find("//x_corr") != std::string::npos)
        {
            modelProcessed << "name x_corr : nonce @";
            for (size_t i = 0; i < serverCount; ++i)
            {
                modelProcessed << element.servers[i];
                if (i != serverCount - 1)
                    modelProcessed << ",";
            }
            modelProcessed << "\n";
        }

        if (line.find("//time") != std::string::npos)
        {
            size_t serverCount = element.servers.size();
            size_t clientCount = element.clients.size();

            for (int t = 1; t <= 2; ++t)
            {
                modelProcessed << "name time" << t << " : nonce @";

                // 动态拼接 client 名称
                for (size_t i = 0; i < clientCount; ++i)
                {
                    modelProcessed << element.clients[i];
                    if (i != clientCount - 1 || serverCount > 0)
                        modelProcessed << ",";
                }

                if (serverCount == 1)
                {
                    modelProcessed << element.servers[0]; // 直接接上 Server
                }
                else
                {
                    for (size_t i = 0; i < serverCount; ++i)
                    {
                        modelProcessed << element.servers[i];
                        if (i != serverCount - 1)
                            modelProcessed << ",";
                    }
                }

                modelProcessed << "\n";
            }
        }

        if (line.find("//userID") != std::string::npos)
        {
            size_t serverCount = element.servers.size();
            size_t clientCount = element.clients.size();

            for (size_t i = 0; i < clientCount; ++i)
            {
                std::string clientName = element.clients[i];
                modelProcessed << "name user" << clientName << " : nonce @";

                // 加入所有客户端名称
                for (size_t j = 0; j < clientCount; ++j)
                {
                    modelProcessed << element.clients[j];
                    if (j != clientCount - 1 || serverCount > 0)
                        modelProcessed << ",";
                }

                // 加入服务器名称
                if (serverCount == 1)
                {
                    modelProcessed << element.servers[0]; // 单个服务器
                }
                else
                {
                    for (size_t j = 0; j < serverCount; ++j)
                    {
                        modelProcessed << element.servers[j];
                        if (j != serverCount - 1)
                            modelProcessed << ",";
                    }
                }

                modelProcessed << "\n";
            }
        }

        if (line.find("//output A2S_MSG1 msg") != std::string::npos)
        {
            size_t serverCount = element.servers.size();
            std::string output1, output2;

            if (serverCount == 1)
            {
                output1 = "let _ = output A2S_MSG1(get(userA), m1, get(time1)) to endpoint(" + element.servers[0] + ") in\n";
                output2 = "let _ = output A2S_MSG2(get(userA), m2, get(time2)) to endpoint(" + element.servers[0] + ") in\n";
            }
            else
            {
                // 默认将消息发往第一个服务器
                output1 = "let _ = output A2S_MSG1(get(userA), m1, get(time1)) to endpoint(" + element.servers[0] + ") in\n";
                output2 = "let _ = output A2S_MSG2(get(userA), m2, get(time2)) to endpoint(" + element.servers[0] + ") in\n";
            }

            modelProcessed << output1;
            modelProcessed << output2;
        }
    }
    modelFile.close();

    // ===== 2. 定制处理 server3.txt，支持替换 Server 为各 server 名 =====
    std::filesystem::path serverPath = std::filesystem::current_path() / "src" / "AttackModel" / (element.server_type + ".txt");
    std::ifstream serverFile(serverPath);
    if (!serverFile)
    {
        std::cerr << "❌ 无法打开 server 文件: " << serverPath << std::endl;
        return "";
    }

    std::stringstream serverBuffer;
    serverBuffer << serverFile.rdbuf();
    std::string serverTemplate = serverBuffer.str();
    serverFile.close();

    std::string finalServerContent;
    for (const auto &serverName : element.servers)
    {
        std::string customized = serverTemplate;
        size_t pos = 0;
        while ((pos = customized.find("Server", pos)) != std::string::npos)
        {
            customized.replace(pos, 6, serverName);
            pos += serverName.length();
        }

        // === 保存原始模板用于查找标记 ===
        std::string originalTemplate = serverTemplate;
        
        // === 插入第一段 output AS2BS_MSG1 和 AS2BS_MSG2 ===
        // 查找第一个"//output MSG1&MSG2"标记位置（在原始模板中查找）
        size_t first_marker = originalTemplate.find("//output MSG1&MSG2");
        if (first_marker != std::string::npos)
        {
            // 计算替换后的实际位置
            size_t actual_first_marker = 0;
            size_t offset = 0;
            
            // 计算从开始到标记位置的替换偏移量
            pos = 0;
            while ((pos = serverTemplate.find("Server", pos)) != std::string::npos && pos < first_marker)
            {
                offset += serverName.length() - 6;
                pos += 6;
            }
            
            actual_first_marker = first_marker + offset;
            
            // 定位到标记所在行的行尾位置
            size_t first_line_start = customized.find('\n', actual_first_marker);
            if (first_line_start != std::string::npos)
            {
                std::string inject1;
                
                // 根据服务器名称决定消息路由逻辑
                if (serverName == "AServer")
                {
                    inject1 =
                        "let _ = output S2B_MSG1(get(userA),get(x_corr), t1) to endpoint(BServer) in\n"
                        "let _ = output S2B_MSG2(get(userA),x1, t2) to endpoint(BServer) in\n";
                }
                else if (serverName == "BServer")
                {
                    inject1 =
                        "let _ = output MSG1 to endpoint(B) in\n"
                        "let _ = output MSG2 to endpoint(B) in\n";
                }
                else
                {
                    // 默认使用原始逻辑
                    if (element.servers.size() == 1)
                    {
                        inject1 =
                            "let _ = output S2B_MSG1(get(userA),get(x_corr), t1) to endpoint(" + serverName + ") in\n"
                            "let _ = output S2B_MSG2(get(userA),x1, t2) to endpoint(" + serverName + ") in\n";
                    }
                    else
                    {
                        inject1 =
                            "let _ = output S2B_MSG1(get(userA),get(x_corr), t1) to endpoint(BServer) in\n"
                            "let _ = output S2B_MSG2(get(userA),x1, t2) to endpoint(BServer) in\n";
                    }
                }

                // 在第一个标记行之后插入第一段代码
                customized.insert(first_line_start + 1, inject1);
                offset += inject1.length();

                // 查找第二个"//output MSG1&MSG2"标记位置（在原始模板中查找）
                size_t second_marker = originalTemplate.find("//output MSG1&MSG2", first_marker + 1);
                if (second_marker != std::string::npos)
                {
                    // 计算第二个标记的替换后位置
                    size_t actual_second_marker = second_marker;
                    pos = 0;
                    size_t second_offset = 0;
                    
                    while ((pos = serverTemplate.find("Server", pos)) != std::string::npos && pos < second_marker)
                    {
                        second_offset += serverName.length() - 6;
                        pos += 6;
                    }
                    
                    second_offset += offset;
                    actual_second_marker = second_marker + second_offset;
                    
                    // 定位到第二个标记所在行的行尾位置
                    size_t second_line_start = customized.find('\n', actual_second_marker);
                    if (second_line_start != std::string::npos)
                    {
                        // 第二段插入内容固定为向B端点发送MSG1和MSG2
                        std::string inject2 =
                            "let _ = output MSG1 to endpoint(B) in\n"
                            "let _ = output MSG2 to endpoint(B) in\n";
                        // 在第二个标记行之后插入第二段代码
                        customized.insert(second_line_start + 1, inject2);
                    }
                }
            }
        }

        finalServerContent += "// ===== Injected for server: " + serverName + " =====\n";
        finalServerContent += customized + "\n";
    }

    // === 插入主函数定义到最后 ===
    if (element.servers.size() == 1)
    {
        finalServerContent +=
            "\n"
            "def A_main() @A : Unit = call A_send_MSG()\n"
            "def Server_main() @Server : Unit = call Server_transfer_MSG()\n"
            "def B_main() @B : Result = call B_accept_MSG()\n";
    }
    else
    {
        finalServerContent +=
            "\n"
            "def A_main() @A : Unit = call A_send_MSG()\n"
            "def AServer_main() @AServer : Unit = call AServer_transfer_MSG()\n"
            "def BServer_main() @BServer : Unit = call BServer_transfer_MSG()\n"
            "def B_main() @B : Result = call B_accept_MSG()\n";
    }

    // 拼接最终结果
    return modelProcessed.str() + "\n" + finalServerContent;
}
void OwlGenerator::generate(const CoreElement &element, const std::string &outputPath)
{
    std::ofstream outFile(outputPath);
    if (!outFile)
    {
        std::cerr << "❌ 无法写入文件: " << outputPath << std::endl;
        return;
    }

    if (element.model_type == "model4" && element.server_type == "server3")
    { // 仅针对model4+server3
        outFile << genModel4AndServer3(element);
    }
    else
    {
        outFile << genLocalityClient(element.clients);
        outFile << genLocalityServer(element.servers);
        outFile << genDynamicUserAndCorr(element.clients, element.servers);
        outFile << genParams(element);
        outFile << genKeys(element);
        outFile << genCorr(element);
        outFile << genDH_Hash(element);
        outFile << genMessages(element);
        outFile << genDR_Hash(element);

        outFile << genClientProcess(element);
        outFile << genServerProcess(element);

        outFile << genClientMainProcess(element.clients);
        outFile << genServerMainProcess(element.servers);
    }

    std::cout << "sucess OwlGenerator" << std::endl;
}
