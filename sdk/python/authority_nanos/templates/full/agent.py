#!/usr/bin/env python3
"""
{{PROJECT_NAME}} - Full-Featured Authority Nanos Agent

A comprehensive agent demonstrating all Authority Kernel capabilities.

Created: {{DATE}}
"""

import json
import logging
import os
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from authority_nanos import AuthorityKernel, TypedHeap

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("{{PROJECT_NAME}}")


@dataclass
class AgentState:
    """Agent state structure."""
    status: str = "initialized"
    task_count: int = 0
    error_count: int = 0
    last_activity: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class Task:
    """Task structure."""
    id: str
    name: str
    status: str = "pending"
    result: Optional[str] = None
    created_at: str = None
    completed_at: Optional[str] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()


class StateManager:
    """Manages agent state using Authority Kernel's typed heap."""

    def __init__(self, kernel: AuthorityKernel):
        self.heap = TypedHeap(kernel)
        self._state_handle = None
        self._task_handles: Dict[str, dict] = {}
        self._initialize_state()

    def _initialize_state(self):
        """Initialize the agent state."""
        initial_state = AgentState()
        data = json.dumps(asdict(initial_state)).encode()
        self._state_handle = self.heap.alloc("agent_state", data)
        logger.info(f"State initialized with handle: {self._state_handle}")

    def get_state(self) -> AgentState:
        """Get current agent state."""
        data = self.heap.read(self._state_handle)
        state_dict = json.loads(data.decode())
        return AgentState(**state_dict)

    def update_state(self, **updates) -> int:
        """Update agent state with given fields."""
        current = self.get_state()
        for key, value in updates.items():
            if hasattr(current, key):
                setattr(current, key, value)

        # Build JSON patch
        patch_ops = [
            {"op": "replace", "path": f"/{key}", "value": value}
            for key, value in updates.items()
        ]
        patch = json.dumps(patch_ops).encode()
        return self.heap.write(self._state_handle, patch)

    def create_task(self, task_id: str, name: str) -> Task:
        """Create a new task."""
        task = Task(id=task_id, name=name)
        data = json.dumps(asdict(task)).encode()
        handle = self.heap.alloc(f"task:{task_id}", data)
        self._task_handles[task_id] = handle
        logger.info(f"Created task '{name}' with id: {task_id}")
        return task

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get a task by ID."""
        if task_id not in self._task_handles:
            return None
        data = self.heap.read(self._task_handles[task_id])
        task_dict = json.loads(data.decode())
        return Task(**task_dict)

    def update_task(self, task_id: str, **updates) -> Optional[int]:
        """Update a task."""
        if task_id not in self._task_handles:
            return None

        patch_ops = [
            {"op": "replace", "path": f"/{key}", "value": value}
            for key, value in updates.items()
        ]
        patch = json.dumps(patch_ops).encode()
        return self.heap.write(self._task_handles[task_id], patch)

    def complete_task(self, task_id: str, result: str) -> bool:
        """Mark a task as completed."""
        if task_id not in self._task_handles:
            return False

        self.update_task(
            task_id,
            status="completed",
            result=result,
            completed_at=datetime.now().isoformat()
        )
        logger.info(f"Task {task_id} completed")
        return True

    def list_tasks(self) -> List[Task]:
        """List all tasks."""
        tasks = []
        for task_id in self._task_handles:
            task = self.get_task(task_id)
            if task:
                tasks.append(task)
        return tasks

    def delete_task(self, task_id: str) -> bool:
        """Delete a task."""
        if task_id not in self._task_handles:
            return False
        self.heap.delete(self._task_handles[task_id])
        del self._task_handles[task_id]
        logger.info(f"Task {task_id} deleted")
        return True

    def cleanup(self):
        """Clean up all state."""
        for task_id in list(self._task_handles.keys()):
            self.delete_task(task_id)
        if self._state_handle:
            self.heap.delete(self._state_handle)
            self._state_handle = None
        logger.info("State cleaned up")


class ConfigManager:
    """Manages configuration from config.json."""

    def __init__(self, config_path: str = "config.json"):
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        default_config = {
            "agent_name": "{{PROJECT_NAME}}",
            "log_level": "INFO",
            "max_tasks": 100,
            "task_timeout_seconds": 300,
            "features": {
                "auto_cleanup": True,
                "verbose_logging": False
            }
        }

        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    loaded = json.load(f)
                    default_config.update(loaded)
                    logger.info(f"Loaded config from {self.config_path}")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}, using defaults")

        return default_config

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value."""
        keys = key.split(".")
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value


class Agent:
    """Main agent class."""

    def __init__(self, config: ConfigManager, state_manager: StateManager):
        self.config = config
        self.state = state_manager
        self._running = False

    def start(self):
        """Start the agent."""
        logger.info(f"Starting {self.config.get('agent_name')}...")
        self._running = True
        self.state.update_state(
            status="running",
            last_activity=datetime.now().isoformat()
        )

    def stop(self):
        """Stop the agent."""
        logger.info("Stopping agent...")
        self._running = False
        self.state.update_state(
            status="stopped",
            last_activity=datetime.now().isoformat()
        )

    def execute_task(self, name: str) -> Optional[str]:
        """Execute a task."""
        if not self._running:
            logger.error("Agent not running")
            return None

        # Create task
        task_id = f"task_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        task = self.state.create_task(task_id, name)

        # Update state
        current = self.state.get_state()
        self.state.update_state(
            task_count=current.task_count + 1,
            last_activity=datetime.now().isoformat()
        )

        # Simulate task execution
        logger.info(f"Executing task: {name}")
        try:
            # Task logic would go here
            result = f"Task '{name}' completed successfully"
            self.state.complete_task(task_id, result)
            return result
        except Exception as e:
            error_msg = f"Task failed: {e}"
            self.state.update_task(task_id, status="failed", result=error_msg)
            self.state.update_state(error_count=current.error_count + 1)
            logger.error(error_msg)
            return None

    def get_status(self) -> Dict[str, Any]:
        """Get agent status."""
        state = self.state.get_state()
        tasks = self.state.list_tasks()
        return {
            "state": asdict(state),
            "tasks": {
                "total": len(tasks),
                "pending": len([t for t in tasks if t.status == "pending"]),
                "completed": len([t for t in tasks if t.status == "completed"]),
                "failed": len([t for t in tasks if t.status == "failed"])
            }
        }


def main():
    """Main entry point."""
    print("=" * 60)
    print(f"  {{PROJECT_NAME}} - Full-Featured Agent")
    print("  Running with Authority Kernel")
    print("=" * 60)
    print()

    # Load configuration
    logger.info("Loading configuration...")
    config = ConfigManager()

    # Set log level from config
    log_level = config.get("log_level", "INFO")
    logging.getLogger().setLevel(getattr(logging, log_level, logging.INFO))

    # Initialize Authority Kernel
    logger.info("Initializing Authority Kernel...")
    kernel = AuthorityKernel()
    state_manager = StateManager(kernel)

    # Create agent
    agent = Agent(config, state_manager)

    try:
        # Start agent
        agent.start()

        # Execute some tasks
        print("\n[1] Running sample tasks...")
        agent.execute_task("Initialize system")
        agent.execute_task("Process data")
        agent.execute_task("Generate report")

        # Show status
        print("\n[2] Agent Status:")
        status = agent.get_status()
        print(f"    State: {status['state']['status']}")
        print(f"    Tasks completed: {status['tasks']['completed']}")
        print(f"    Total tasks: {status['tasks']['total']}")

        # List tasks
        print("\n[3] Task History:")
        for task in state_manager.list_tasks():
            print(f"    - {task.name}: {task.status}")

        # Interactive mode (optional)
        if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
            print("\n[4] Interactive Mode (type 'quit' to exit)")
            while True:
                try:
                    task_name = input("\nTask name: ").strip()
                    if task_name.lower() in ("quit", "exit", "q"):
                        break
                    if task_name:
                        result = agent.execute_task(task_name)
                        print(f"Result: {result}")
                except KeyboardInterrupt:
                    break

    finally:
        # Stop and cleanup
        agent.stop()
        if config.get("features.auto_cleanup", True):
            state_manager.cleanup()

    print("\n" + "=" * 60)
    print("  Agent finished successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
