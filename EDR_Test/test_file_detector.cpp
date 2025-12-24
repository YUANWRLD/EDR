#include "pch.h" 
#include <gtest/gtest.h>
#include "FileDetector.h"


class FileDetectorTest : public ::testing::Test {
protected:
    FileDetector* detector;

    void SetUp() override {
        detector = new FileDetector();
    }

    void TearDown() override {
        delete detector;
    }
};

// ------------------------------------------------------------------------
// Test Case 1: 測試標準的 Chrome/Edge 路徑 (Positive Case)
// ------------------------------------------------------------------------
TEST_F(FileDetectorTest, DetectsStandardLoginDataPaths) {

    std::wstring chromePath = L"C:\\Users\\bombe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data";
    EXPECT_TRUE(detector->Analyze(chromePath)) << "Should detect Chrome Login Data";

    std::wstring edgePath = L"C:\\Users\\User\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data";
    EXPECT_TRUE(detector->Analyze(edgePath)) << "Should detect Edge Login Data";
}

// ------------------------------------------------------------------------
// Test Case 2: 測試大小寫不敏感 (Case Insensitivity)
// ------------------------------------------------------------------------
TEST_F(FileDetectorTest, IgnoresCaseDifferences) {

    EXPECT_TRUE(detector->Analyze(L"C:\\USERS\\ADMIN\\LOGIN DATA"));

    EXPECT_TRUE(detector->Analyze(L"C:\\Users\\Admin\\loGiN DaTa"));
}

// ------------------------------------------------------------------------
// Test Case 3: 測試正常檔案 (Negative Case)
// ------------------------------------------------------------------------
TEST_F(FileDetectorTest, IgnoresSafeFiles) {

    EXPECT_FALSE(detector->Analyze(L"C:\\Windows\\System32\\kernel32.dll"));

    EXPECT_FALSE(detector->Analyze(L"C:\\Users\\User\\Documents\\ProjectProposal.docx"));

    EXPECT_FALSE(detector->Analyze(L"C:\\Users\\User\\Desktop\\Login_Script.bat"));
}

// ------------------------------------------------------------------------
// Test Case 4: 邊界測試 (Edge Cases)
// ------------------------------------------------------------------------
TEST_F(FileDetectorTest, HandlesEmptyAndWeirdPaths) {

    EXPECT_FALSE(detector->Analyze(L""));

    EXPECT_TRUE(detector->Analyze(L"Login Data"));

    EXPECT_TRUE(detector->Analyze(L"D:\\Backup\\2025\\Chrome_Login Data.bak"));
}