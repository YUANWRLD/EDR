#include "pch.h"
#include "gtest/gtest.h"
#include "ProcessAccessDetector.h" 

TEST(ProcessAccessDetectorTest, DetectsAccessToVictim) {

    ProcessAccessDetector detector;
    detector.SetVictimPid(1234);
    detector.AddWhitelist(L"Taskmgr.exe");

    std::vector<std::pair<std::wstring, bool>> testCases = {
        { L"malv1.exe", true },          
        { L"Taskmgr.exe", false },       
        { L"taskMGR.exe", false },        
		{ L"notepad.exe", true },     
        { L"ttaskmgr.exe", true },      
        { L"fake_Taskmgr.exe", true }    
    };

    for (const auto& testCase : testCases) {
        std::wstring attackerName = testCase.first;
        bool expected = testCase.second;
        std::string nameStr;
        nameStr.reserve(attackerName.size());
        for (wchar_t wc : attackerName) {
            nameStr.push_back(static_cast<char>(wc));
        }
        SCOPED_TRACE("Testing Attacker Name: " + nameStr);
  
        bool result = detector.IsAccessingVictim(1234, attackerName);
   
        EXPECT_EQ(result, expected);
	}

}