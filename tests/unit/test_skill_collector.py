"""Tests for sentinel.collector.skill_collector."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from watchdog.events import FileCreatedEvent, FileDeletedEvent, FileModifiedEvent, FileMovedEvent

from sentinel.collector.skill_collector import SkillCollector, _SkillHandler
from sentinel.models.event import Event
from sentinel.models.skill import SkillProfile


def _emit_capture():
    events = []

    def emit(e: Event):
        events.append(e)

    return emit, events


# ── _SkillHandler ─────────────────────────────────────────────────────────────


class TestSkillHandler:
    def test_ignores_non_skill_files(self, tmp_path):
        emit, events = _emit_capture()
        handler = _SkillHandler(emit)
        handler.dispatch(FileCreatedEvent(str(tmp_path / "README.md")))
        assert events == []

    def test_ignores_non_file_events(self, tmp_path):
        emit, events = _emit_capture()
        handler = _SkillHandler(emit)
        handler.dispatch(FileMovedEvent(str(tmp_path / "SKILL.md"), str(tmp_path / "other.md")))
        assert events == []

    def test_new_skill_emits_medium_event(self, tmp_path):
        skill_file = tmp_path / "my-skill" / "SKILL.md"
        skill_file.parent.mkdir(parents=True)
        skill_file.write_text("# Skill")

        emit, events = _emit_capture()
        handler = _SkillHandler(emit)

        profile = MagicMock(spec=SkillProfile)
        profile.trust_score = "TRUSTED"
        profile.injection_risk = "LOW"

        with patch.object(handler._analyzer, "analyze", return_value=profile):
            handler.dispatch(FileCreatedEvent(str(skill_file)))

        assert len(events) == 1
        assert events[0].event_type == "new_skill"
        assert events[0].severity == "MEDIUM"

    def test_quarantine_skill_escalates_to_high(self, tmp_path):
        skill_file = tmp_path / "bad-skill" / "SKILL.md"
        skill_file.parent.mkdir(parents=True)
        skill_file.write_text("# Bad Skill")

        emit, events = _emit_capture()
        handler = _SkillHandler(emit)

        profile = MagicMock(spec=SkillProfile)
        profile.trust_score = "QUARANTINE"
        profile.injection_risk = "HIGH"

        with patch.object(handler._analyzer, "analyze", return_value=profile):
            handler.dispatch(FileCreatedEvent(str(skill_file)))

        assert events[0].severity == "HIGH"

    def test_modified_skill_emits_low_event(self, tmp_path):
        skill_file = tmp_path / "my-skill" / "SKILL.md"
        skill_file.parent.mkdir(parents=True)
        skill_file.write_text("# Skill")

        emit, events = _emit_capture()
        handler = _SkillHandler(emit)

        profile = MagicMock(spec=SkillProfile)
        profile.trust_score = "TRUSTED"
        profile.injection_risk = "LOW"

        with patch.object(handler._analyzer, "analyze", return_value=profile):
            handler.dispatch(FileModifiedEvent(str(skill_file)))

        assert events[0].event_type == "modified_skill"
        assert events[0].severity == "LOW"

    def test_deleted_skill_emits_info_event(self, tmp_path):
        skill_file = tmp_path / "my-skill" / "SKILL.md"
        emit, events = _emit_capture()
        handler = _SkillHandler(emit)
        handler.dispatch(FileDeletedEvent(str(skill_file)))

        assert events[0].event_type == "deleted_skill"
        assert events[0].severity == "INFO"

    def test_skill_analysis_error_is_swallowed(self, tmp_path):
        skill_file = tmp_path / "bad-skill" / "SKILL.md"
        skill_file.parent.mkdir(parents=True)
        skill_file.write_text("# Bad")

        emit, events = _emit_capture()
        handler = _SkillHandler(emit)

        with patch.object(handler._analyzer, "analyze", side_effect=RuntimeError("boom")):
            handler.dispatch(FileCreatedEvent(str(skill_file)))

        # Still emits event despite error
        assert len(events) == 1

    def test_event_entity_is_skill_name(self, tmp_path):
        skill_file = tmp_path / "my-cool-skill" / "SKILL.md"
        emit, events = _emit_capture()
        handler = _SkillHandler(emit)
        handler.dispatch(FileDeletedEvent(str(skill_file)))

        assert events[0].entity == "my-cool-skill"


# ── SkillCollector ────────────────────────────────────────────────────────────


class TestSkillCollector:
    def test_start_watches_existing_dir(self, tmp_path):
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()

        emit, _ = _emit_capture()
        config = MagicMock()
        config.skills_dir = skills_dir
        config.workspace_skills_dir = tmp_path / "nonexistent"

        collector = SkillCollector(config, emit)

        mock_observer = MagicMock()
        with patch("sentinel.collector.skill_collector.Observer", return_value=mock_observer):
            collector.start()

        mock_observer.schedule.assert_called_once()
        mock_observer.start.assert_called_once()

    def test_start_skips_nonexistent_dir(self, tmp_path):
        emit, _ = _emit_capture()
        config = MagicMock()
        config.skills_dir = tmp_path / "nonexistent-a"
        config.workspace_skills_dir = tmp_path / "nonexistent-b"

        collector = SkillCollector(config, emit)

        mock_observer = MagicMock()
        with patch("sentinel.collector.skill_collector.Observer", return_value=mock_observer):
            collector.start()

        mock_observer.schedule.assert_not_called()

    def test_start_handles_permission_error_on_schedule(self, tmp_path):
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()

        emit, _ = _emit_capture()
        config = MagicMock()
        config.skills_dir = skills_dir
        config.workspace_skills_dir = tmp_path / "nonexistent"

        collector = SkillCollector(config, emit)

        mock_observer = MagicMock()
        mock_observer.schedule.side_effect = PermissionError("denied")
        with patch("sentinel.collector.skill_collector.Observer", return_value=mock_observer):
            collector.start()  # Should not raise

    def test_stop_joins_observer(self, tmp_path):
        emit, _ = _emit_capture()
        config = MagicMock()
        config.skills_dir = tmp_path / "nonexistent"
        config.workspace_skills_dir = tmp_path / "nonexistent2"

        collector = SkillCollector(config, emit)

        mock_observer = MagicMock()
        with patch("sentinel.collector.skill_collector.Observer", return_value=mock_observer):
            collector.start()
            collector.stop()

        mock_observer.stop.assert_called_once()
        mock_observer.join.assert_called_once()

    def test_stop_is_safe_when_not_started(self):
        emit, _ = _emit_capture()
        config = MagicMock()
        collector = SkillCollector(config, emit)
        collector.stop()  # Should not raise — observer is None
