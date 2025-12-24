#include "pch.h"
#include "gtest/gtest.h"
#include "BehaviorTracker.h"

class BehaviorTrackerTest : public ::testing::Test {
protected:
    BehaviorTracker tracker;
};

// 測試案例 1: 單一行為不應觸發警報
TEST_F(BehaviorTrackerTest, SingleActionDoesNotTrigger) {
    bool result = tracker.AddBehavior(100, SuspiciousAction::RegistryAccess, L"RegKey_A");

    EXPECT_FALSE(result) << "Single action should not trigger detection";
    
    auto logs = tracker.GetLogs(100);
    ASSERT_EQ(logs.size(), 1);
    EXPECT_NE(logs[0].find(L"[Registry]"), std::wstring::npos);
}

// 測試案例 2: 累積兩種不同行為應觸發警報 (閾值測試)
TEST_F(BehaviorTrackerTest, TwoDifferentActionsTriggerDetection) {
    tracker.AddBehavior(100, SuspiciousAction::RegistryAccess, L"RegKey_A");
    
    bool result = tracker.AddBehavior(100, SuspiciousAction::FileAccess, L"secret.txt");

    EXPECT_TRUE(result) << "Two different actions should trigger detection";
    
    auto logs = tracker.GetLogs(100);
    EXPECT_EQ(logs.size(), 2);
}

// 測試案例 3: 同類型的行為重複發生，分數不應增加
TEST_F(BehaviorTrackerTest, DuplicateActionTypeDoesNotIncreaseScore) {

    tracker.AddBehavior(100, SuspiciousAction::RegistryAccess, L"RegKey_A");
    
    bool result = tracker.AddBehavior(100, SuspiciousAction::RegistryAccess, L"RegKey_B");

    EXPECT_FALSE(result);
    
    auto logs = tracker.GetLogs(100);
    EXPECT_EQ(logs.size(), 1) << "Duplicate action type should not add new logs based on current logic";
}

// 測試案例 4: 已被偵測過的 PID，不應再次回傳 true (鎖定機制)
TEST_F(BehaviorTrackerTest, AlreadyDetectedPidShouldNotTriggerAgain) {
    tracker.AddBehavior(100, SuspiciousAction::RegistryAccess, L"Reg");
    EXPECT_TRUE(tracker.AddBehavior(100, SuspiciousAction::FileAccess, L"File")); 
    

    bool result = tracker.AddBehavior(100, SuspiciousAction::ProcessAccess, L"ProcessInject");
    EXPECT_FALSE(result) << "Already detected PID should return false to prevent spamming alerts";
}

// 測試案例 5: 不同 PID 之間應該互不影響
TEST_F(BehaviorTrackerTest, DifferentPidsAreIndependent) {

    tracker.AddBehavior(100, SuspiciousAction::RegistryAccess, L"Reg");

    bool result = tracker.AddBehavior(200, SuspiciousAction::FileAccess, L"File");

    EXPECT_FALSE(result);
    
    EXPECT_TRUE(tracker.AddBehavior(100, SuspiciousAction::ProcessAccess, L"Proc"));
}

// 測試案例 6: 清除 PID 資料
TEST_F(BehaviorTrackerTest, RemovePidClearsData) {
    tracker.AddBehavior(100, SuspiciousAction::RegistryAccess, L"Reg");

    tracker.RemovePid(100);

    EXPECT_TRUE(tracker.GetLogs(100).empty());
    
    tracker.AddBehavior(100, SuspiciousAction::RegistryAccess, L"Reg");
    auto logs = tracker.GetLogs(100);
    EXPECT_EQ(logs.size(), 1);
}