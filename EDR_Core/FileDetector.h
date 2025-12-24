#pragma once
#include <string>
#include <vector>

class FileDetector {
public:
    FileDetector();
    ~FileDetector();

    bool Analyze(const std::wstring& filePath);

private:
    std::wstring ToLower(const std::wstring& str);
};