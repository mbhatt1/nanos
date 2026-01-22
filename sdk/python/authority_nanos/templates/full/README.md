# {{PROJECT_NAME}}

A full-featured Authority Nanos agent with comprehensive capabilities.

## Features

- Structured state management with dataclasses
- Task tracking and execution
- Configuration management
- Comprehensive security policy
- Logging and audit support
- Unit tests included

## Getting Started

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run in simulation mode:
   ```bash
   python agent.py
   ```

3. Run in interactive mode:
   ```bash
   python agent.py --interactive
   ```

4. Run with Authority Kernel:
   ```bash
   authority run agent.py --policy policy.json
   ```

5. Run tests:
   ```bash
   pytest tests/
   ```

## Project Structure

```
{{PROJECT_NAME}}/
|-- agent.py          # Main agent implementation
|-- policy.json       # Security policy
|-- config.json       # Runtime configuration
|-- requirements.txt  # Python dependencies
|-- tests/
|   |-- test_agent.py # Unit tests
|-- .gitignore        # Git ignore rules
```

## Configuration

Edit `config.json` to customize agent behavior:

```json
{
  "agent_name": "{{PROJECT_NAME}}",
  "log_level": "INFO",
  "max_tasks": 100,
  "features": {
    "auto_cleanup": true,
    "verbose_logging": false
  }
}
```

## Security Policy

The policy (`policy.json`) enables:
- Heap operations with up to 100MB storage
- Network access to LLM APIs
- Filesystem access to config, data, and log directories
- Environment variable access for API keys
- Audit logging for all operations

## Architecture

### StateManager
Manages agent state and tasks using the Authority Kernel's typed heap.

```python
state_manager = StateManager(kernel)
state_manager.update_state(status="running")
state_manager.create_task("task_1", "Process data")
```

### ConfigManager
Loads and provides access to configuration from `config.json`.

```python
config = ConfigManager()
log_level = config.get("log_level", "INFO")
auto_cleanup = config.get("features.auto_cleanup", True)
```

### Agent
Main agent class that orchestrates state and task execution.

```python
agent = Agent(config, state_manager)
agent.start()
agent.execute_task("My task")
agent.stop()
```

## Extending the Agent

### Adding New Task Types

```python
def execute_custom_task(self, data: dict) -> str:
    task_id = self.state.create_task(...)
    # Custom logic here
    self.state.complete_task(task_id, result)
    return result
```

### Adding External Integrations

The policy allows network access to LLM APIs. Add integrations in `agent.py`:

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4")
response = llm.invoke("Your prompt")
```

## Learn More

- [Authority Nanos Documentation](https://authority-systems.github.io/nanos)
- [Policy Format Reference](https://authority-systems.github.io/nanos/policy/)
- [API Reference](https://authority-systems.github.io/nanos/api/)
- [Security Best Practices](https://authority-systems.github.io/nanos/security/)
