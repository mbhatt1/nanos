# {{PROJECT_NAME}}

A minimal Authority Nanos agent demonstrating basic heap operations.

## Getting Started

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the agent in simulation mode:
   ```bash
   python agent.py
   ```

3. Run with Authority Kernel:
   ```bash
   authority run agent.py --policy policy.json
   ```

## Project Structure

- `agent.py` - Main agent code with heap operations
- `policy.json` - Security policy defining allowed capabilities
- `requirements.txt` - Python dependencies

## Policy

The policy file (`policy.json`) defines what the agent is allowed to do:
- Heap operations (alloc, read, write, delete)
- No network access
- No filesystem access

## Learn More

- [Authority Nanos Documentation](https://authority-systems.github.io/nanos)
- [Policy Format Reference](https://authority-systems.github.io/nanos/policy/)
- [API Reference](https://authority-systems.github.io/nanos/api/)
