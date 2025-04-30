#include "CoreElementParser.h"
#include "OwlGenerator.h"
#include <iostream>
#include <filesystem>

int main() {
    std::cout << "当前工作目录：" << std::filesystem::current_path() << std::endl;

    CoreElementParser parser;
    CoreElement ce = parser.parse("coreElement.txt");

    OwlGenerator generator;
    generator.generate(ce, "output.owl");

    std::cout << "✅ OwlLang 模型生成成功，文件已写入 output.owl" << std::endl;
    std::cout <<"test sucess";
    return 0;
}
