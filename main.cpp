#include "CoreElementParser.h"
#include "OwlGenerator.h"
#include <iostream>
#include <filesystem>
#include <chrono>

int main()
{

    CoreElementParser parser;
    CoreElement ce = parser.parse("coreElement.txt");

    OwlGenerator generator;
    generator.generate(ce, "output.owl");

    std::cout << "✅ OwlLang 模型生成成功，文件已写入 output.owl" << std::endl;

    return 0;
}
