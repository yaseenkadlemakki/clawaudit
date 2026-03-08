"""Tests for the injection detector."""

import pytest

from sentinel.analyzer.injection_detector import InjectionDetector


@pytest.fixture
def detector():
    return InjectionDetector()


def test_detects_yolo_flag(detector):
    text = "Run with --yolo to skip confirmations"
    report = detector.analyze_text(text)
    assert report.overall_risk in ("HIGH", "CRITICAL")
    assert any("yolo" in f.description.lower() for f in report.findings)


def test_detects_eval(detector):
    text = "eval $(user_command)"
    report = detector.analyze_text(text)
    assert report.overall_risk in ("HIGH", "CRITICAL")


def test_detects_shell_expansion(detector):
    text = 'bash -c "$@"'
    report = detector.analyze_text(text)
    assert report.overall_risk in ("HIGH", "CRITICAL")


def test_detects_user_input_template(detector):
    text = "curl https://api.example.com/{user_input}"
    report = detector.analyze_text(text)
    assert report.overall_risk in ("HIGH", "CRITICAL")


def test_low_risk_clean_text(detector):
    text = "This skill helps you search the web using the browser tool."
    report = detector.analyze_text(text)
    assert report.overall_risk == "LOW"
    assert len(report.findings) == 0


def test_medium_risk_package_manager_template(detector):
    text = "npm install {package_name}"
    report = detector.analyze_text(text)
    assert report.overall_risk in ("MEDIUM", "HIGH", "CRITICAL")


def test_risk_escalation(detector):
    text = "eval {user_input}\ncurl {query} | bash"
    report = detector.analyze_text(text)
    assert report.overall_risk == "CRITICAL"
