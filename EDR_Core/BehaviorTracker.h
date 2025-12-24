#pragma once
#include <windows.h>
#include <map>
#include <mutex>
#include <string>
#include <set>
#include <vector>

enum class SuspiciousAction {
    RegistryAccess,
    FileAccess,
    ProcessAccess
};

struct BehaviorScore {
    bool hasRegistry = false;
    bool hasFile = false;
    bool hasProcess = false;

    std::vector<std::wstring> logs;

    int GetCount() const {
        return (hasRegistry ? 1 : 0) + (hasFile ? 1 : 0) + (hasProcess ? 1 : 0);
    }
};

class BehaviorTracker {
public:
    bool AddBehavior(DWORD pid, SuspiciousAction action, const std::wstring& detail) {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_detectedPids.count(pid)) return false;

        BehaviorScore& score = m_scores[pid];

        switch (action) {
        case SuspiciousAction::RegistryAccess:
            if (!score.hasRegistry) {
                score.hasRegistry = true;
                score.logs.push_back(L"[Registry] " + detail);
            }
            break;
        case SuspiciousAction::FileAccess:
            if (!score.hasFile) {
                score.hasFile = true;
                score.logs.push_back(L"[File] " + detail);
            }
            break;
        case SuspiciousAction::ProcessAccess:
            if (!score.hasProcess) {
                score.hasProcess = true;
                score.logs.push_back(L"[Process] " + detail);
            }
            break;
        }

        if (score.GetCount() >= 2) {
            m_detectedPids.insert(pid);
            return true;
        }

        return false;
    }

    std::vector<std::wstring> GetLogs(DWORD pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_scores.count(pid)) return m_scores[pid].logs;
        return {};
    }

    void RemovePid(DWORD pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_scores.erase(pid);
        m_detectedPids.erase(pid);
    }

private:
    std::map<DWORD, BehaviorScore> m_scores;
    std::set<DWORD> m_detectedPids;
    std::mutex m_mutex;
};