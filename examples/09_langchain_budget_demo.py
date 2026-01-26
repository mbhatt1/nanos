#!/usr/bin/env python3
"""
Example 9: LangChain Agent with Budget Tracking

Demonstrates integration of LangChain agents with Authority Kernel budget tracking.
This example shows how to monitor resource consumption in real-time while running
a LangChain agent with tools.

Features:
- LangChain agent with custom tools
- Real-time budget monitoring
- Token usage tracking
- Tool call counting
- Budget alerts and warnings
- Remaining time estimation

Works in simulation mode (no kernel build required).
"""

import json
import sys
import time
from typing import Any, Dict, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass

SIMULATION_MODE = True  # Set to False when running with real kernel

try:
    from authority_nanos import AuthorityKernel
    HAVE_KERNEL = True
except ImportError:
    HAVE_KERNEL = False
    SIMULATION_MODE = True


@dataclass
class SimulatedBudgetStatus:
    """Simulated budget status for demo."""
    tokens_used: int
    tokens_limit: int
    tool_calls_used: int
    tool_calls_limit: int
    wall_time_used: int
    wall_time_limit: int
    bytes_used: int
    bytes_limit: int
    
    @property
    def tokens_percent(self) -> float:
        return (self.tokens_used / self.tokens_limit * 100) if self.tokens_limit > 0 else 0
    
    @property
    def tool_calls_percent(self) -> float:
        return (self.tool_calls_used / self.tool_calls_limit * 100) if self.tool_calls_limit > 0 else 0
    
    @property
    def wall_time_percent(self) -> float:
        return (self.wall_time_used / self.wall_time_limit * 100) if self.wall_time_limit > 0 else 0
    
    @property
    def tokens_remaining(self) -> int:
        return max(0, self.tokens_limit - self.tokens_used)
    
    @property
    def tool_calls_remaining(self) -> int:
        return max(0, self.tool_calls_limit - self.tool_calls_used)
    
    @property
    def is_any_critical(self) -> bool:
        return any([
            self.tokens_percent >= 90,
            self.tool_calls_percent >= 90,
            self.wall_time_percent >= 90
        ])


@dataclass
class SimulatedSnapshot:
    """Simulated budget snapshot."""
    timestamp: datetime
    tokens: int
    tool_calls: int
    wall_time_ms: int


@dataclass
class SimulatedBreakdown:
    """Simulated budget breakdown."""
    tokens_by_operation: Dict[str, int]
    tool_calls_by_name: Dict[str, int]
    
    def top_token_consumers(self, n: int) -> List[tuple]:
        return sorted(self.tokens_by_operation.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def top_tools(self, n: int) -> List[tuple]:
        return sorted(self.tool_calls_by_name.items(), key=lambda x: x[1], reverse=True)[:n]


class SimulatedBudgetTracker:
    """Simulated budget tracker for demo."""
    
    def __init__(self):
        self.status = SimulatedBudgetStatus(
            tokens_used=0,
            tokens_limit=100000,
            tool_calls_used=0,
            tool_calls_limit=50,
            wall_time_used=0,
            wall_time_limit=300000,  # 5 minutes
            bytes_used=0,
            bytes_limit=10485760  # 10MB
        )
        self.snapshots: List[SimulatedSnapshot] = []
        self.start_time = datetime.now()
        self.operation_tokens = {}
        self.tool_calls = {}
    
    def get_status(self, force_refresh: bool = False):
        """Get current budget status."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        self.status.wall_time_used = int(elapsed * 1000)
        return self.status
    
    def get_history(self, count: int = 60) -> List[SimulatedSnapshot]:
        """Get historical snapshots."""
        return self.snapshots[-count:]
    
    def get_breakdown(self) -> SimulatedBreakdown:
        """Get detailed breakdown."""
        return SimulatedBreakdown(
            tokens_by_operation=self.operation_tokens.copy(),
            tool_calls_by_name=self.tool_calls.copy()
        )
    
    def estimate_remaining_runtime(self) -> Optional[timedelta]:
        """Estimate remaining runtime."""
        if len(self.snapshots) < 2:
            return None
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        if elapsed < 1:
            return None
        
        token_rate = self.status.tokens_used / elapsed
        if token_rate < 0.1:
            return timedelta(hours=999)
        
        remaining_tokens = self.status.tokens_remaining
        remaining_seconds = remaining_tokens / token_rate
        return timedelta(seconds=int(remaining_seconds))
    
    def print_status(self, detailed: bool = False):
        """Print budget status."""
        s = self.status
        print(f"\nBudget Status:")
        print(f"  Tokens:     {s.tokens_used:,} / {s.tokens_limit:,} ({s.tokens_percent:.1f}%)")
        print(f"  Tool Calls: {s.tool_calls_used} / {s.tool_calls_limit} ({s.tool_calls_percent:.1f}%)")
        print(f"  Wall Time:  {s.wall_time_used/1000:.1f}s / {s.wall_time_limit/1000:.1f}s ({s.wall_time_percent:.1f}%)")
        
        if detailed:
            print(f"  Bytes:      {s.bytes_used:,} / {s.bytes_limit:,}")
    
    def record_inference(self, tokens_used: int):
        """Record inference operation."""
        self.status.tokens_used += tokens_used
        self.operation_tokens['inference'] = self.operation_tokens.get('inference', 0) + tokens_used
        self._snapshot()
    
    def record_tool_call(self, tool_name: str, tokens_used: int):
        """Record tool call."""
        self.status.tool_calls_used += 1
        self.status.tokens_used += tokens_used
        self.tool_calls[tool_name] = self.tool_calls.get(tool_name, 0) + 1
        self.operation_tokens['tool_response'] = self.operation_tokens.get('tool_response', 0) + tokens_used
        self._snapshot()
    
    def _snapshot(self):
        """Take a snapshot."""
        self.snapshots.append(SimulatedSnapshot(
            timestamp=datetime.now(),
            tokens=self.status.tokens_used,
            tool_calls=self.status.tool_calls_used,
            wall_time_ms=self.status.wall_time_used
        ))


class SimulatedKernel:
    """Simulated Authority Kernel for demo."""
    
    def __init__(self):
        self.budget = SimulatedBudgetTracker()
        self._authorized_tools = {'calculator', 'get_time', 'word_count'}
    
    def authorize(self, effect_type: str, resource: str) -> bool:
        """Check authorization."""
        if effect_type == 'tool':
            return resource in self._authorized_tools
        return True
    
    def inference(self, request_data: bytes) -> bytes:
        """Simulate inference."""
        tokens_used = 150  # Simulate token usage
        self.budget.record_inference(tokens_used)
        
        request = json.loads(request_data.decode('utf-8'))
        messages = request.get('messages', [])
        
        # Get the last user message
        user_msg = None
        for msg in reversed(messages):
            if msg.get('role') == 'user' and 'Tool result:' not in msg.get('content', ''):
                user_msg = msg.get('content', '')
                break
        
        # Generate appropriate response based on content
        if user_msg:
            prompt_lower = user_msg.lower()
            
            if 'time' in prompt_lower or 'date' in prompt_lower:
                content = "TOOL: get_time\nINPUT: now"
            elif 'count' in prompt_lower and 'word' in prompt_lower:
                if 'in:' in user_msg:
                    text = user_msg.split('in:')[1].strip()
                    content = f"TOOL: word_count\nINPUT: {text}"
                else:
                    content = "TOOL: word_count\nINPUT: hello world"
            elif any(op in user_msg for op in ['+', '-', '*', '/', 'calculate', 'divided']):
                import re
                if 'divided by' in prompt_lower:
                    parts = prompt_lower.split('divided by')
                    if len(parts) == 2:
                        try:
                            a = ''.join(c for c in parts[0] if c.isdigit() or c == '.')
                            b = ''.join(c for c in parts[1] if c.isdigit() or c == '.')
                            content = f"TOOL: calculator\nINPUT: {a}/{b}"
                        except:
                            content = "TOOL: calculator\nINPUT: 2+2"
                    else:
                        content = "TOOL: calculator\nINPUT: 2+2"
                else:
                    math_expr = re.findall(r'[\d\s+\-*/().]+', user_msg)
                    if math_expr:
                        expr = math_expr[0].strip()
                        if any(c.isdigit() for c in expr):
                            content = f"TOOL: calculator\nINPUT: {expr}"
                        else:
                            content = "TOOL: calculator\nINPUT: 2+2"
                    else:
                        content = "TOOL: calculator\nINPUT: 2+2"
            elif 'Tool result:' in user_msg:
                # This is a follow-up after tool execution
                result = user_msg.replace('Tool result:', '').strip()
                content = f"Based on the tool execution, the answer is: {result}"
            else:
                content = f"I understand you asked: '{user_msg[:50]}'. This is a simulated response."
        else:
            content = "Simulated response"
        
        response = {
            'content': content,
            'tokens': tokens_used
        }
        return json.dumps(response).encode('utf-8')
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass


class BudgetMonitor:
    """
    Real-time budget monitor that tracks resource consumption.
    
    This class provides callbacks and monitoring functionality to track
    budget consumption during LangChain agent execution.
    """
    
    def __init__(self, kernel, warn_threshold: float = 75.0, critical_threshold: float = 90.0):
        """
        Initialize budget monitor.
        
        Args:
            kernel: AuthorityKernel instance
            warn_threshold: Warning threshold percentage (default 75%)
            critical_threshold: Critical threshold percentage (default 90%)
        """
        self.kernel = kernel
        self.warn_threshold = warn_threshold
        self.critical_threshold = critical_threshold
        self.start_time = datetime.now()
        self.warnings_issued = set()
    
    def check_and_alert(self) -> Dict[str, Any]:
        """
        Check budget status and issue alerts if needed.
        
        Returns:
            Dictionary with alert information
        """
        status = self.kernel.budget.get_status(force_refresh=True)
        
        alerts = {
            'status': 'ok',
            'warnings': [],
            'critical': []
        }
        
        # Check each resource
        resources = [
            ('tokens', status.tokens_percent, status.tokens_remaining),
            ('tool_calls', status.tool_calls_percent, status.tool_calls_remaining),
            ('time', status.wall_time_percent, None)
        ]
        
        for resource_name, percent, remaining in resources:
            if percent >= self.critical_threshold:
                alerts['status'] = 'critical'
                msg = f"{resource_name}: {percent:.1f}% used"
                if remaining is not None:
                    msg += f" ({remaining} remaining)"
                alerts['critical'].append(msg)
            elif percent >= self.warn_threshold:
                if resource_name not in self.warnings_issued:
                    alerts['status'] = 'warning' if alerts['status'] != 'critical' else 'critical'
                    msg = f"{resource_name}: {percent:.1f}% used"
                    if remaining is not None:
                        msg += f" ({remaining} remaining)"
                    alerts['warnings'].append(msg)
                    self.warnings_issued.add(resource_name)
        
        return alerts
    
    def print_status_summary(self):
        """Print a concise status summary."""
        status = self.kernel.budget.get_status()
        elapsed = datetime.now() - self.start_time
        
        print(f"\nBudget Summary (Elapsed: {str(elapsed).split('.')[0]})")
        print("-" * 60)
        print(f"  Tokens:     {status.tokens_used:,} / {status.tokens_limit:,} ({status.tokens_percent:.1f}%)")
        print(f"  Tool Calls: {status.tool_calls_used} / {status.tool_calls_limit} ({status.tool_calls_percent:.1f}%)")
        print(f"  Wall Time:  {status.wall_time_used/1000:.1f}s / {status.wall_time_limit/1000:.1f}s ({status.wall_time_percent:.1f}%)")
        
        # Estimate remaining time
        remaining = self.kernel.budget.estimate_remaining_runtime()
        if remaining and str(remaining) != 'inf':
            print(f"  Est. Remaining: ~{str(remaining).split('.')[0]}")


class AuthorityLangChainAgent:
    """
    LangChain-compatible agent with Authority Kernel integration.
    
    This agent wraps LangChain functionality with Authority Kernel's
    budget tracking and policy enforcement.
    """
    
    def __init__(self, kernel, name: str = "Agent", model: str = "gpt-4", 
                 tools: Optional[list] = None):
        """
        Initialize LangChain agent with Authority Kernel.
        
        Args:
            kernel: AuthorityKernel instance
            name: Agent name
            model: LLM model to use
            tools: List of tool functions
        """
        self.kernel = kernel
        self.name = name
        self.model = model
        self.tools = tools or []
        self.conversation_history = []
        self.tool_call_count = 0
    
    def add_tool(self, name: str, description: str, func):
        """Add a tool to the agent."""
        self.tools.append({
            'name': name,
            'description': description,
            'func': func
        })
    
    def invoke(self, prompt: str, verbose: bool = True) -> str:
        """
        Invoke the agent with a prompt.
        
        Args:
            prompt: User prompt
            verbose: Print progress information
            
        Returns:
            Agent's response
        """
        if verbose:
            print(f"\n[{self.name}] Processing: {prompt[:60]}...")
        
        # Build system message with tool descriptions
        tool_descriptions = "\n".join([
            f"- {t['name']}: {t['description']}" for t in self.tools
        ])
        
        system_msg = f"""You are {self.name}, a helpful AI assistant.

Available tools:
{tool_descriptions if tool_descriptions else "(No tools available)"}

To use a tool, respond with:
TOOL: tool_name
INPUT: tool_input

Otherwise, answer directly."""
        
        # Add to conversation history
        self.conversation_history.append({'role': 'user', 'content': prompt})
        
        # Simulate LLM call through Authority Kernel
        messages = [{'role': 'system', 'content': system_msg}] + self.conversation_history
        
        try:
            # Make inference request
            request_data = json.dumps({
                'model': self.model,
                'messages': messages,
                'max_tokens': 300
            }).encode('utf-8')
            
            response = self.kernel.inference(request_data)
            result = json.loads(response.decode('utf-8'))
            
            # Extract response
            if 'content' in result:
                response_text = result['content']
            elif 'choices' in result and result['choices']:
                response_text = result['choices'][0].get('message', {}).get('content', '')
            else:
                response_text = "I processed your request."
            
        except Exception as e:
            if verbose:
                print(f"  Note: Using simulated response ({e})")
            response_text = self._simulate_response(prompt)
        
        # Check if tool use is requested
        if 'TOOL:' in response_text and 'INPUT:' in response_text:
            tool_name, tool_input = self._parse_tool_request(response_text)
            if tool_name and tool_input:
                tool_result = self._execute_tool(tool_name, tool_input, verbose)
                
                # Get final response with tool result
                self.conversation_history.append({'role': 'assistant', 'content': response_text})
                self.conversation_history.append({'role': 'user', 'content': f"Tool result: {tool_result}"})
                
                # Get final answer
                try:
                    request_data = json.dumps({
                        'model': self.model,
                        'messages': [{'role': 'system', 'content': system_msg}] + self.conversation_history,
                        'max_tokens': 200
                    }).encode('utf-8')
                    
                    response = self.kernel.inference(request_data)
                    result = json.loads(response.decode('utf-8'))
                    response_text = result.get('content', tool_result)
                except:
                    response_text = f"Based on the tool result: {tool_result}"
        
        self.conversation_history.append({'role': 'assistant', 'content': response_text})
        
        if verbose:
            print(f"[{self.name}] Response: {response_text[:100]}...")
        
        return response_text
    
    def _simulate_response(self, prompt: str) -> str:
        """Simulate a response for demo purposes."""
        prompt_lower = prompt.lower()
        
        if 'time' in prompt_lower or 'date' in prompt_lower:
            return "TOOL: get_time\nINPUT: now"
        elif 'count' in prompt_lower and 'word' in prompt_lower:
            # Extract text after "in:"
            if 'in:' in prompt:
                text = prompt.split('in:')[1].strip()
                return f"TOOL: word_count\nINPUT: {text}"
            return "TOOL: word_count\nINPUT: hello world"
        elif any(op in prompt for op in ['+', '-', '*', '/', 'calculate', 'divided']):
            # Extract math expression
            import re
            # Look for patterns like "15 * 7 + 3" or "100 divided by 5"
            if 'divided by' in prompt_lower:
                parts = prompt_lower.split('divided by')
                if len(parts) == 2:
                    try:
                        a = ''.join(c for c in parts[0] if c.isdigit() or c == '.')
                        b = ''.join(c for c in parts[1] if c.isdigit() or c == '.')
                        return f"TOOL: calculator\nINPUT: {a}/{b}"
                    except:
                        pass
            
            # Try to extract mathematical expression
            math_expr = re.findall(r'[\d\s+\-*/().]+', prompt)
            if math_expr:
                expr = math_expr[0].strip()
                if any(c.isdigit() for c in expr):
                    return f"TOOL: calculator\nINPUT: {expr}"
            
            return "TOOL: calculator\nINPUT: 2+2"
        else:
            return f"I understand you asked: '{prompt[:50]}'. This is a simulated response in demo mode."
    
    def _parse_tool_request(self, text: str) -> tuple:
        """Parse tool request from response."""
        lines = text.split('\n')
        tool_name = None
        tool_input = None
        
        for line in lines:
            if line.startswith('TOOL:'):
                tool_name = line.replace('TOOL:', '').strip()
            elif line.startswith('INPUT:'):
                tool_input = line.replace('INPUT:', '').strip()
        
        return tool_name, tool_input
    
    def _execute_tool(self, tool_name: str, tool_input: str, verbose: bool) -> str:
        """Execute a tool and return result."""
        self.tool_call_count += 1
        
        if verbose:
            print(f"  [{self.name}] Calling tool: {tool_name}({tool_input})")
        
        # Find tool
        tool = next((t for t in self.tools if t['name'] == tool_name), None)
        if not tool:
            return f"Error: Tool '{tool_name}' not found"
        
        # Check authorization
        if not self.kernel.authorize('tool', tool_name):
            return f"Error: Tool '{tool_name}' not authorized"
        
        # Execute tool
        try:
            result = tool['func'](tool_input)
            
            # Record in budget
            if SIMULATION_MODE:
                self.kernel.budget.record_tool_call(tool_name, 50)  # Simulate 50 tokens
            else:
                self.kernel.budget.get_status(force_refresh=True)
            
            if verbose:
                print(f"  [{self.name}] Tool result: {str(result)[:60]}...")
            
            return str(result)
        except Exception as e:
            return f"Error executing tool: {e}"


def create_sample_tools():
    """Create sample tools for demonstration."""
    def calculator(expr: str) -> str:
        """Calculate mathematical expressions."""
        try:
            # Safe evaluation for demo
            allowed_chars = set('0123456789+-*/.() ')
            if not all(c in allowed_chars for c in expr):
                return "Error: Invalid characters"
            result = eval(expr)
            return str(result)
        except Exception as e:
            return f"Error: {e}"
    
    def get_time(input_str: str) -> str:
        """Get current time."""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def word_count(text: str) -> str:
        """Count words in text."""
        words = text.split()
        return f"{len(words)} words"
    
    return [
        ('calculator', 'Performs mathematical calculations', calculator),
        ('get_time', 'Gets the current date and time', get_time),
        ('word_count', 'Counts words in text', word_count),
    ]


def main():
    """Main demonstration function."""
    print("\n" + "=" * 70)
    print("LangChain Agent with Budget Tracking Demo")
    print("=" * 70)
    
    if SIMULATION_MODE:
        print("\n  Running in SIMULATION MODE (no kernel required)")
    else:
        print("\n  Running with Authority Kernel")
    
    print("\nThis example demonstrates:")
    print("- LangChain agent with custom tools")
    print("- Real-time budget monitoring")
    print("- Resource consumption tracking")
    print("- Budget alerts and warnings")
    print()
    
    try:
        kernel_cls = SimulatedKernel if SIMULATION_MODE else AuthorityKernel
        with kernel_cls() as ak:
            print("[+] Connected to Authority Kernel")
            
            # Create budget monitor
            monitor = BudgetMonitor(ak, warn_threshold=75.0, critical_threshold=90.0)
            print("[+] Budget monitor initialized")
            
            # Show initial budget status
            print("\nInitial Budget Status:")
            ak.budget.print_status()
            
            # Create agent with tools
            print("\n" + "=" * 70)
            print("Creating LangChain Agent")
            print("=" * 70)
            
            agent = AuthorityLangChainAgent(ak, name="ResearchAssistant", model="gpt-4")
            
            # Add tools
            for tool_name, tool_desc, tool_func in create_sample_tools():
                agent.add_tool(tool_name, tool_desc, tool_func)
            
            print(f"[+] Created agent with {len(agent.tools)} tools")
            
            # Run agent tasks with budget monitoring
            print("\n" + "=" * 70)
            print("Running Agent Tasks with Budget Monitoring")
            print("=" * 70)
            
            tasks = [
                "What time is it now?",
                "Calculate 15 * 7 + 3",
                "Count the words in: The quick brown fox jumps over the lazy dog",
                "What is 100 divided by 5?",
            ]
            
            for i, task in enumerate(tasks, 1):
                print(f"\n--- Task {i}/{len(tasks)} ---")
                print(f"Prompt: {task}")
                
                # Execute task
                response = agent.invoke(task, verbose=True)
                
                # Check budget and alert
                alerts = monitor.check_and_alert()
                
                if alerts['status'] == 'critical':
                    print("\n!!! CRITICAL BUDGET ALERT !!!")
                    for msg in alerts['critical']:
                        print(f"  CRITICAL: {msg}")
                    print("Consider stopping execution to avoid budget exhaustion.")
                elif alerts['status'] == 'warning':
                    print("\n! Budget Warning")
                    for msg in alerts['warnings']:
                        print(f"  WARNING: {msg}")
                
                # Show quick status
                status = ak.budget.get_status()
                print(f"\nCurrent: Tokens={status.tokens_used:,}, Tools={status.tool_calls_used}, Time={status.wall_time_used}")
                
                # Small delay between tasks
                time.sleep(0.1)
            
            # Final budget report
            print("\n" + "=" * 70)
            print("Final Budget Report")
            print("=" * 70)
            
            monitor.print_status_summary()
            
            # Show detailed breakdown
            print("\n--- Detailed Breakdown ---")
            breakdown = ak.budget.get_breakdown()
            
            if breakdown.tokens_by_operation:
                print("\nToken Usage by Operation:")
                for op, tokens in breakdown.top_token_consumers(5):
                    print(f"  {op}: {tokens:,} tokens")
            
            if breakdown.tool_calls_by_name:
                print("\nTool Calls:")
                for tool, calls in breakdown.top_tools(5):
                    print(f"  {tool}: {calls} calls")
            
            # Show history graph
            print("\n--- Budget History (last 10 snapshots) ---")
            history = ak.budget.get_history(count=10)
            
            if history:
                print("\nTime                     Tokens  Tool Calls")
                print("-" * 50)
                for snapshot in history[-10:]:
                    time_str = snapshot.timestamp.strftime("%H:%M:%S")
                    print(f"{time_str}              {snapshot.tokens:6d}  {snapshot.tool_calls:10d}")
            
            # Final detailed status
            print("\n--- Complete Budget Status ---")
            ak.budget.print_status(detailed=True)
            
            print("\n" + "=" * 70)
            print("Demo Complete")
            print("=" * 70)
            print("\nKey Observations:")
            print(f"- Total tasks completed: {len(tasks)}")
            print(f"- Total tool calls made: {agent.tool_call_count}")
            print(f"- Final token usage: {status.tokens_used:,} / {status.tokens_limit:,}")
            print(f"- Budget health: {'OK' if not status.is_any_critical else 'CRITICAL'}")
            print()
            
            return 0
            
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
