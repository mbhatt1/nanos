#!/usr/bin/env python3
"""
Tests for {{PROJECT_NAME}} agent.

Run with: pytest tests/test_agent.py -v
"""

import json
import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent import (
    AgentState,
    Task,
    StateManager,
    ConfigManager,
    Agent,
)


class MockTypedHeap:
    """Mock TypedHeap for testing without Authority Kernel."""

    def __init__(self):
        self._objects = {}
        self._next_id = 1

    def alloc(self, type_name: str, data: bytes) -> dict:
        obj_id = self._next_id
        self._next_id += 1
        self._objects[obj_id] = {
            "type": type_name,
            "data": data,
            "version": 1
        }
        return {"id": obj_id, "version": 1}

    def read(self, handle: dict) -> bytes:
        obj_id = handle["id"]
        if obj_id not in self._objects:
            raise KeyError(f"Object {obj_id} not found")
        return self._objects[obj_id]["data"]

    def write(self, handle: dict, patch: bytes) -> int:
        obj_id = handle["id"]
        if obj_id not in self._objects:
            raise KeyError(f"Object {obj_id} not found")

        obj = self._objects[obj_id]
        current = json.loads(obj["data"].decode())

        # Apply JSON patch
        for op in json.loads(patch.decode()):
            if op["op"] == "replace":
                path = op["path"].lstrip("/")
                if "/" in path:
                    # Nested path not supported in mock
                    pass
                else:
                    current[path] = op["value"]

        obj["data"] = json.dumps(current).encode()
        obj["version"] += 1
        return obj["version"]

    def delete(self, handle: dict):
        obj_id = handle["id"]
        if obj_id in self._objects:
            del self._objects[obj_id]


class TestAgentState:
    """Tests for AgentState dataclass."""

    def test_default_values(self):
        state = AgentState()
        assert state.status == "initialized"
        assert state.task_count == 0
        assert state.error_count == 0
        assert state.last_activity is None
        assert state.metadata == {}

    def test_custom_values(self):
        state = AgentState(
            status="running",
            task_count=5,
            metadata={"key": "value"}
        )
        assert state.status == "running"
        assert state.task_count == 5
        assert state.metadata == {"key": "value"}


class TestTask:
    """Tests for Task dataclass."""

    def test_default_values(self):
        task = Task(id="test_1", name="Test Task")
        assert task.id == "test_1"
        assert task.name == "Test Task"
        assert task.status == "pending"
        assert task.result is None
        assert task.created_at is not None
        assert task.completed_at is None

    def test_custom_values(self):
        task = Task(
            id="test_2",
            name="Custom Task",
            status="completed",
            result="Success"
        )
        assert task.status == "completed"
        assert task.result == "Success"


class TestStateManager:
    """Tests for StateManager class."""

    @pytest.fixture
    def state_manager(self):
        """Create a StateManager with mock heap."""
        mock_kernel = Mock()
        with patch("agent.TypedHeap", return_value=MockTypedHeap()):
            from agent import StateManager
            # Re-import to get fresh class
            manager = StateManager.__new__(StateManager)
            manager.heap = MockTypedHeap()
            manager._state_handle = None
            manager._task_handles = {}
            manager._initialize_state()
            return manager

    def test_initialize_state(self, state_manager):
        assert state_manager._state_handle is not None

    def test_get_state(self, state_manager):
        state = state_manager.get_state()
        assert isinstance(state, AgentState)
        assert state.status == "initialized"

    def test_update_state(self, state_manager):
        state_manager.update_state(status="running", task_count=1)
        state = state_manager.get_state()
        assert state.status == "running"
        assert state.task_count == 1

    def test_create_task(self, state_manager):
        task = state_manager.create_task("task_1", "Test Task")
        assert task.id == "task_1"
        assert task.name == "Test Task"
        assert "task_1" in state_manager._task_handles

    def test_get_task(self, state_manager):
        state_manager.create_task("task_1", "Test Task")
        task = state_manager.get_task("task_1")
        assert task is not None
        assert task.name == "Test Task"

    def test_get_nonexistent_task(self, state_manager):
        task = state_manager.get_task("nonexistent")
        assert task is None

    def test_complete_task(self, state_manager):
        state_manager.create_task("task_1", "Test Task")
        result = state_manager.complete_task("task_1", "Done")
        assert result is True

        task = state_manager.get_task("task_1")
        assert task.status == "completed"
        assert task.result == "Done"

    def test_list_tasks(self, state_manager):
        state_manager.create_task("task_1", "Task 1")
        state_manager.create_task("task_2", "Task 2")

        tasks = state_manager.list_tasks()
        assert len(tasks) == 2

    def test_delete_task(self, state_manager):
        state_manager.create_task("task_1", "Test Task")
        result = state_manager.delete_task("task_1")
        assert result is True
        assert "task_1" not in state_manager._task_handles

    def test_cleanup(self, state_manager):
        state_manager.create_task("task_1", "Task 1")
        state_manager.cleanup()
        assert len(state_manager._task_handles) == 0
        assert state_manager._state_handle is None


class TestConfigManager:
    """Tests for ConfigManager class."""

    def test_default_config(self, tmp_path):
        config = ConfigManager(config_path=str(tmp_path / "nonexistent.json"))
        assert config.get("agent_name") == "{{PROJECT_NAME}}"
        assert config.get("log_level") == "INFO"

    def test_load_config(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "agent_name": "Custom Agent",
            "log_level": "DEBUG"
        }))

        config = ConfigManager(config_path=str(config_file))
        assert config.get("agent_name") == "Custom Agent"
        assert config.get("log_level") == "DEBUG"

    def test_get_nested_value(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "features": {
                "auto_cleanup": False
            }
        }))

        config = ConfigManager(config_path=str(config_file))
        assert config.get("features.auto_cleanup") is False

    def test_get_default_value(self, tmp_path):
        config = ConfigManager(config_path=str(tmp_path / "nonexistent.json"))
        assert config.get("nonexistent", "default") == "default"


class TestAgent:
    """Tests for Agent class."""

    @pytest.fixture
    def agent(self, tmp_path):
        """Create an Agent with mocks."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "agent_name": "Test Agent",
            "features": {"auto_cleanup": True}
        }))

        config = ConfigManager(config_path=str(config_file))

        mock_kernel = Mock()
        with patch("agent.TypedHeap", return_value=MockTypedHeap()):
            from agent import StateManager
            manager = StateManager.__new__(StateManager)
            manager.heap = MockTypedHeap()
            manager._state_handle = None
            manager._task_handles = {}
            manager._initialize_state()

            return Agent(config, manager)

    def test_start(self, agent):
        agent.start()
        assert agent._running is True
        state = agent.state.get_state()
        assert state.status == "running"

    def test_stop(self, agent):
        agent.start()
        agent.stop()
        assert agent._running is False
        state = agent.state.get_state()
        assert state.status == "stopped"

    def test_execute_task(self, agent):
        agent.start()
        result = agent.execute_task("Test Task")
        assert result is not None
        assert "completed successfully" in result

    def test_execute_task_when_not_running(self, agent):
        result = agent.execute_task("Test Task")
        assert result is None

    def test_get_status(self, agent):
        agent.start()
        agent.execute_task("Task 1")
        agent.execute_task("Task 2")

        status = agent.get_status()
        assert status["state"]["status"] == "running"
        assert status["tasks"]["total"] == 2
        assert status["tasks"]["completed"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
