#pragma once
#include <string>
#include <algorithm>
#include <vector>

class RegistryDetector {
public:
    RegistryDetector() {}

    bool Analyze(const std::wstring& registryPath) {
        std::wstring lowerPath = registryPath;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

        if (lowerPath.find(L"software") == std::wstring::npos) {
            return false;
        }

        if (lowerPath.find(L"bombe") == std::wstring::npos) {
            return false;
        }

        if (lowerPath.find(L"\\registry\\user") != std::wstring::npos) {
            return false;
        }

        return true;
    }

private:
    std::vector<std::wstring> m_targetSubstrings;
};