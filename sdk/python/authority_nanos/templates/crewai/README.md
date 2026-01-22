# {{PROJECT_NAME}}

A CrewAI multi-agent system running in the Authority Kernel secure environment.

## Features

- Multiple AI agents working together (Researcher, Writer, Reviewer)
- Shared memory for agent coordination via Authority Kernel
- Policy-controlled inter-agent communication
- Sequential task execution with handoffs

## Getting Started

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set your OpenAI API key:
   ```bash
   export OPENAI_API_KEY='your-key-here'
   ```

3. Run in simulation mode:
   ```bash
   python agent.py
   ```

4. Run with Authority Kernel:
   ```bash
   authority run agent.py --policy policy.json
   ```

## Project Structure

- `agent.py` - CrewAI multi-agent setup with Authority Kernel integration
- `policy.json` - Security policy for multi-agent coordination
- `requirements.txt` - Python dependencies

## Agent Roles

### Research Analyst
- Gathers information on the given topic
- Saves findings to shared memory

### Content Writer
- Reads research from shared memory
- Creates article drafts

### Quality Reviewer
- Reviews and improves content
- Produces final output

## Shared Memory

Agents coordinate through Authority Kernel's typed heap:

```python
# Save data
shared_memory.write("key", {"data": "value"}, agent_id="researcher")

# Read data
data = shared_memory.read("key")

# List all keys
keys = shared_memory.list_keys()
```

## Security Policy

The policy enables:
- Large heap allocation (50MB) for multi-agent state
- Shared memory access between agents
- HTTPS access to LLM APIs
- Up to 10 concurrent agents

## Customization

### Adding New Agents

```python
def create_custom_agent(llm) -> Agent:
    return Agent(
        role="Custom Role",
        goal="Agent's goal",
        backstory="Agent's backstory",
        tools=[save_to_shared_memory, read_from_shared_memory],
        llm=llm
    )
```

### Parallel Execution

Change the process type for parallel task execution:

```python
crew = Crew(
    agents=[...],
    tasks=[...],
    process=Process.hierarchical,  # or Process.sequential
)
```

## Learn More

- [CrewAI Documentation](https://docs.crewai.com/)
- [Authority Nanos Documentation](https://authority-systems.github.io/nanos)
- [Multi-Agent Security](https://authority-systems.github.io/nanos/security/)
