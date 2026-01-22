# Authority Nanos Jupyter Notebooks

Interactive tutorials for learning the Authority Nanos Python SDK.

## Prerequisites

- Python 3.8 or later
- Jupyter Notebook or JupyterLab

## Installation

1. Install Jupyter:
   ```bash
   pip install jupyter
   ```

2. Install the Authority Nanos SDK:
   ```bash
   pip install authority-nanos
   ```

   Or install from source:
   ```bash
   cd sdk/python
   pip install -e .
   ```

## Running the Notebooks

Start Jupyter:
```bash
jupyter notebook
```

Or with JupyterLab:
```bash
jupyter lab
```

Then navigate to the `notebooks/` directory and open any notebook.

## Notebooks

### 01_getting_started.ipynb

**Introduction to Authority Nanos**

- What is Authority Nanos
- Installing the SDK
- Hello World example
- Basic heap operations (alloc, read, write, delete)

Start here if you're new to Authority Nanos.

### 02_authorization.ipynb

**Capability-Based Authorization**

- How capability-based authorization works
- Creating and checking capabilities
- Policy configuration in simulation mode
- Handling authorization denials
- Pattern-based policies (advanced)

Learn how to secure your applications with fine-grained access control.

### 03_building_agents.ipynb

**Building AI Agents**

- Agent architecture overview
- Tool execution through the kernel
- LLM inference
- Building an agent loop
- Agent state management
- Handling policy constraints

Build secure AI agents that respect authorization boundaries.

### 04_langchain_integration.ipynb

**LangChain Integration**

- Setting up LangChain with Authority Nanos
- Running LLM calls through the kernel
- Creating policy-controlled tools
- Building a secure LangChain agent
- Agent memory with typed heap

Integrate Authority Nanos with the popular LangChain framework.

## Simulation Mode

All notebooks use **simulation mode** by default (`simulate=True`). This means:

- No kernel binary required
- No LLM API keys needed
- All operations run in-memory
- Perfect for learning and testing

To run against a real kernel, change `simulate=True` to `simulate=False`:

```python
# Simulation mode (default for tutorials)
with AuthorityKernel(simulate=True) as ak:
    ...

# Real kernel mode
with AuthorityKernel(simulate=False) as ak:
    ...
```

## Tips

1. **Run cells in order**: Each notebook is designed to be run top-to-bottom.

2. **Restart kernel if stuck**: If something goes wrong, use Kernel > Restart.

3. **Check the SDK docs**: For more details, see the [documentation](https://authority-systems.github.io/nanos/).

4. **Experiment**: Modify the examples to explore different scenarios.

## Troubleshooting

### ImportError: No module named 'authority_nanos'

Install the SDK:
```bash
pip install authority-nanos
```

### Kernel not found

Make sure you're using a Python kernel that has the SDK installed.

### Simulation mode not working

Ensure you're passing `simulate=True` to `AuthorityKernel()`.

## Further Reading

- [Getting Started Guide](../docs/getting-started/)
- [API Reference](../docs/api/)
- [Security Documentation](../docs/security/)
- [Policy Configuration](../docs/policy/)
