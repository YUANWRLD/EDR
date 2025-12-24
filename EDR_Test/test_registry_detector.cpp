#include "pch.h"
#include "gtest/gtest.h"
#include "RegistryDetector.h" 

TEST(RegistryDetectorTest, DetectsAccessToBombeKey) {

    RegistryDetector detector;

    
    std::vector<std::pair<std::wstring, bool>> testCases = {
        { L"\\REGISTRY\\MACHINE\\SOFTWARE\\BOMBE", true },

        { L"SOFTWARE\\BOMBE", true },

        { L"\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\BOMBE", true },

        { L"\\REGISTRY\\USER\\S-1-5-21-XXX-XXX\\SOFTWARE\\BOMBE", false },

        { L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\BOMBE", false },
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT", false }

    };

    for (const auto& testCase : testCases) {
        std::wstring path = testCase.first;
        bool expected = testCase.second;

        std::string pathStr;
        pathStr.reserve(path.size());
        for (wchar_t wc : path) {
            pathStr.push_back(static_cast<char>(wc));
        }

        SCOPED_TRACE("Testing Path: " + pathStr);

        EXPECT_EQ(detector.Analyze(path), expected);
    }
}