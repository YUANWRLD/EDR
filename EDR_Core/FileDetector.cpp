#include "pch.h"
#include "FileDetector.h"
#include <algorithm>
#include <cwctype>

FileDetector::FileDetector() {}

FileDetector::~FileDetector() {}

bool FileDetector::Analyze(const std::wstring& filePath) {
    if (filePath.empty()) return false;

    std::wstring lowerPath = ToLower(filePath);

    if (lowerPath.find(L"login data") != std::wstring::npos) {
        return true;
    }

    return false;
}

std::wstring FileDetector::ToLower(const std::wstring& str) {
    std::wstring lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    return lower;
}