from auditor import SAMPLE_LOGS, analyze_logs


def test_analyze_logs_flags_brute_force_and_compromise():
    lines = SAMPLE_LOGS.strip().splitlines()
    report = analyze_logs(lines, threshold=5)

    assert report["total_lines_scanned"] == 9
    assert report["total_failed_attempts"] == 7
    assert report["total_accepted_logins"] == 2
    assert len(report["flagged_brute_force_ips"]) == 1

    flagged = report["flagged_brute_force_ips"][0]
    assert flagged["ip"] == "185.220.101.42"
    assert flagged["failed_attempts"] == 5
    assert flagged["compromise_alert"] is True
    assert flagged["targeted_users"] == ["admin", "root", "ubuntu"]


def test_analyze_logs_high_threshold_returns_no_flags():
    lines = SAMPLE_LOGS.strip().splitlines()
    report = analyze_logs(lines, threshold=10)
    assert report["flagged_brute_force_ips"] == []
