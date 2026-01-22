# {{PROJECT_NAME}}

A LangChain-based AI agent running in the Authority Kernel secure environment.

## Features

- LangChain ReAct agent with custom tools
- Secure state management using Authority Kernel's typed heap
- Policy-controlled access to LLM APIs
- Interactive conversation mode

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

- `agent.py` - LangChain agent with Authority Kernel integration
- `policy.json` - Security policy (allows OpenAI API access)
- `requirements.txt` - Python dependencies

## Security Policy

The policy grants:
- Heap access for state management
- HTTPS access to OpenAI API (api.openai.com)
- Read access to OPENAI_API_KEY environment variable

Network access is restricted to the configured LLM providers only.

## Customization

### Using Different LLM Providers

Modify `agent.py` to use other providers:

```python
# For Anthropic Claude
from langchain_anthropic import ChatAnthropic
llm = ChatAnthropic(model="claude-3-opus-20240229")
```

Update `policy.json` to allow the provider's API endpoint.

### Adding Custom Tools

Add tools in the `create_authority_tools()` function:

```python
def my_custom_tool(input_str: str) -> str:
    # Your tool logic here
    return result

tools.append(Tool(
    name="my_tool",
    func=my_custom_tool,
    description="Description for the LLM"
))
```

## Learn More

- [LangChain Documentation](https://python.langchain.com/)
- [Authority Nanos Documentation](https://authority-systems.github.io/nanos)
- [Policy Format Reference](https://authority-systems.github.io/nanos/policy/)
