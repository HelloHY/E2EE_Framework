#include "CoreElementParser.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <regex>

CoreElement CoreElementParser::parse(const std::string &filepath)
{
    CoreElement ce;
    std::ifstream file(filepath);
    std::string line, currentSection;

    while (getline(file, line))
    {
        if (line.find("//") == 0)
        {
            currentSection = line.substr(2);
        }
        else if (!line.empty())
        {
            std::stringstream ss(line);
            std::string key, token;

            if (currentSection == "roles")
            {
                std::string firstLine, secondLine;
                getline(ss, firstLine);
                getline(file, secondLine); // 读取第二行

                std::stringstream firstLineSS(firstLine);
                while (firstLineSS >> token)
                {
                    ce.clients.push_back(token);
                }

                std::stringstream secondLineSS(secondLine);
                while (secondLineSS >> token)
                {
                    ce.servers.push_back(token);
                }
            }
            else if (currentSection == "DH keys" || currentSection == "Signature keys" ||
                     currentSection == "parameters" || currentSection == "message" || currentSection == "process operations")
            {
                getline(ss, key, ':');
                getline(ss, token);

                // 清理 token 中的花括号
                std::size_t start_pos = token.find("{");
                std::size_t end_pos = token.find("}");
                if (start_pos != std::string::npos && end_pos != std::string::npos && end_pos > start_pos)
                {
                    token = token.substr(start_pos + 1, end_pos - start_pos - 1);
                }

                if (currentSection == "process operations")
                {
                    std::stringstream vs(token);
                    std::string expr;
                    while (getline(vs, expr, ';'))
                    {
                        expr.erase(std::remove_if(expr.begin(), expr.end(), ::isspace), expr.end()); // 去空格
                        if (!expr.empty())
                        {
                            ce.process[key].push_back(expr);
                        }
                    }
                }
                else
                {
                    std::stringstream vs(token);
                    std::string v;
                    while (vs >> v)
                    {
                        if (currentSection == "DH keys")
                            ce.dh_keys[key].push_back(v);
                        else if (currentSection == "Signature keys")
                            ce.sig_keys[key].push_back(v);
                        else if (currentSection == "parameters")
                            ce.parameters[key].push_back(v);
                        else
                            ce.messages[key].push_back(v);
                    }
                }
            }
            else if (currentSection == "dh_hash")
            {
                size_t colon_pos = line.find(':');
                if (colon_pos != std::string::npos)
                {
                    std::string key = line.substr(0, colon_pos);
                    std::string value = line.substr(colon_pos + 1);
                    ce.dh_hash[key] = value;
                }
            }
            else if (currentSection == "dr_hash")
            {
                if (line == "k")
                {
                    ce.dr_hash_output = "name k1 : RO get(SK) ++ get(RK) -> nonce  //RK<i+1>\n"
                                        "uniqueness_by admit\n\n"
                                        "name k2 : RO get(SK) ++ get(RK) -> enckey Name(x)  //MK<i+1>\n"
                                        "uniqueness_by admit";
                    ce.dr_hash_type = "k";
                }
                else if (line == "ratchet")
                {
                    ce.dr_hash_output = "name ratchet : RO get(SK) -> enckey Name(x)\n"
                                        "uniqueness_by admit";
                    ce.dr_hash_type = "ratchet";
                }
            }
            else if (currentSection == "attack model")
            {
                if (line == "model1")
                    ce.model_type = "model1";
                else if (line == "model2")
                    ce.model_type = "model2";
                else if (line == "model3")
                    ce.model_type = "model3";
                else if (line == "model4")
                    ce.model_type = "model4";
            }
            else if (currentSection == "attack model server")
            {
                if (line == "server1")
                    ce.server_type = "server1";
                else if (line == "server2")
                    ce.server_type = "server2";
                else if (line == "server3")
                    ce.server_type = "server3";
            }
            else if (currentSection == "corr")
            {
                std::regex arrow_re(R"(\s*==>\s*)");
                std::sregex_token_iterator iter(line.begin(), line.end(), arrow_re, -1);
                std::sregex_token_iterator end;

                std::vector<std::string> tokens;
                for (; iter != end; ++iter)
                {
                    std::string token = iter->str();
                    token.erase(std::remove_if(token.begin(), token.end(), ::isspace), token.end());
                    if (!token.empty())
                    {
                        tokens.push_back(token);
                    }
                }

                if (tokens.size() >= 2)
                {
                    std::string lhs = tokens[0];
                    std::vector<std::string> rhs_chain(tokens.begin() + 1, tokens.end());

                    // ✅ 插入顺序保留
                    ce.corr_rule.emplace_back(lhs, rhs_chain);
                }
            }
        }
    }

    // 打印解析出的 message 中的 BuploadPKs 字段
    std::cout << "[Debug] 解析后的消息字段：" << std::endl;
    for (const auto &[msg, fields] : ce.messages)
    {
        if (msg == "BuploadPKs")
        {
            std::cout << "BuploadPKs 消息字段: ";
            for (const auto &field : fields)
            {
                std::cout << field << " ";
            }
            std::cout << std::endl;
        }
    }

    std::cout << "success Parser" << std::endl;
    return ce;
}
