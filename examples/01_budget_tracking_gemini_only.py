#!/usr/bin/env python3
"""
Example 11: API-Only Budget Tracking (No Estimation)

This example uses ONLY real API token counts with NO estimation fallbacks.
It demonstrates production-grade token tracking suitable for billing and cost control.

Features:
- 100% accurate token counts from API metadata
- Fail-fast if API metadata unavailable
- Detailed token breakdown (prompt vs completion)
- Transparent source marking
- Production-ready implementation

Requirements:
- Gemini API key (required, no simulation fallback)
- google-genai package: pip install google-genai

Setup:
1. Get API key: https://makersuite.google.com/app/apikey
2. Set: export GEMINI_API_KEY=your_key_here
3. Run: python3 examples/11_api_only_budget.py
"""

import json
import sys
import os
import time
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Check for API key (REQUIRED)
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    print("ERROR: GEMINI_API_KEY environment variable not set")
    print("\nThis example requires a real API key for accurate token tracking.")
    print("Get your key from: https://makersuite.google.com/app/apikey")
    print("\nThen set it:")
    print("  export GEMINI_API_KEY=your_key_here")
    print("  or create a .env file with: GEMINI_API_KEY=your_key_here")
    sys.exit(1)

# Import Gemini SDK
try:
    from google import genai
    client = genai.Client(api_key=GEMINI_API_KEY)
    print("[+] Gemini API configured successfully")
except ImportError:
    print("ERROR: google-genai package not installed")
    print("Install with: pip install google-genai")
    sys.exit(1)
except Exception as e:
    print(f"ERROR: Failed to configure Gemini API: {e}")
    sys.exit(1)


@dataclass
class BudgetStatus:
    """Budget status with real token tracking."""
    tokens_used: int
    tokens_limit: int
    tool_calls_used: int
    tool_calls_limit: int
    wall_time_used: int
    wall_time_limit: int
    
    @property
    def tokens_percent(self) -> float:
        return (self.tokens_used / self.tokens_limit * 100) if self.tokens_limit > 0 else 0
    
    @property
    def tokens_remaining(self) -> int:
        return max(0, self.tokens_limit - self.tokens_used)
    
    @property
    def is_critical(self) -> bool:
        return self.tokens_percent >= 90


@dataclass
class TokenBreakdown:
    """Detailed token breakdown from API."""
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    operation_type: str
    timestamp: datetime
    model: str


class BudgetTracker:
    """Production-grade budget tracker with API-only token counting."""
    
    def __init__(self, token_limit: int = 100000):
        self.status = BudgetStatus(
            tokens_used=0,
            tokens_limit=token_limit,
            tool_calls_used=0,
            tool_calls_limit=50,
            wall_time_used=0,
            wall_time_limit=300000
        )
        self.start_time = datetime.now()
        self.token_history: List[TokenBreakdown] = []
        self.operation_totals = {
            'inference': 0,
            'tool_response': 0
        }
    
    def record_inference(self, prompt_tokens: int, completion_tokens: int, 
                        total_tokens: int, model: str = 'unknown'):
        """Record inference with detailed breakdown."""
        # Validate token counts
        if total_tokens != prompt_tokens + completion_tokens:
            print(f"  [WARNING] Token mismatch: {total_tokens} != {prompt_tokens} + {completion_tokens}")
        
        # Record breakdown
        breakdown = TokenBreakdown(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            operation_type='inference',
            timestamp=datetime.now(),
            model=model
        )
        self.token_history.append(breakdown)
        
        # Update status
        self.status.tokens_used += total_tokens
        self.operation_totals['inference'] += total_tokens
        
        # Update wall time
        elapsed = (datetime.now() - self.start_time).total_seconds()
        self.status.wall_time_used = int(elapsed * 1000)
    
    def record_tool_call(self, tool_name: str):
        """Record tool execution."""
        self.status.tool_calls_used += 1
    
    def get_status(self) -> BudgetStatus:
        """Get current budget status."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        self.status.wall_time_used = int(elapsed * 1000)
        return self.status
    
    def print_status(self):
        """Print formatted status."""
        s = self.status
        print(f"\nBudget Status:")
        print(f"  Tokens:     {s.tokens_used:,} / {s.tokens_limit:,} ({s.tokens_percent:.1f}%)")
        print(f"  Remaining:  {s.tokens_remaining:,}")
        print(f"  Tool Calls: {s.tool_calls_used} / {s.tool_calls_limit}")
        print(f"  Wall Time:  {s.wall_time_used/1000:.1f}s")
        
        if s.is_critical:
            print(f"  STATUS:     CRITICAL")
        else:
            print(f"  STATUS:     OK")
    
    def print_breakdown(self):
        """Print detailed token breakdown."""
        if not self.token_history:
            print("\nNo token history available")
            return
        
        print("\nToken Usage Breakdown:")
        print(f"  Total Operations: {len(self.token_history)}")
        
        total_prompt = sum(b.prompt_tokens for b in self.token_history)
        total_completion = sum(b.completion_tokens for b in self.token_history)
        
        print(f"  Prompt Tokens:     {total_prompt:,}")
        print(f"  Completion Tokens: {total_completion:,}")
        print(f"  Total Tokens:      {self.status.tokens_used:,}")
        
        print("\nBy Operation:")
        for op_type, total in self.operation_totals.items():
            if total > 0:
                percent = (total / self.status.tokens_used * 100) if self.status.tokens_used > 0 else 0
                print(f"  {op_type}: {total:,} ({percent:.1f}%)")
        
        print("\nRecent Operations:")
        for breakdown in self.token_history[-5:]:
            time_str = breakdown.timestamp.strftime("%H:%M:%S")
            print(f"  [{time_str}] {breakdown.operation_type}: "
                  f"prompt={breakdown.prompt_tokens}, "
                  f"completion={breakdown.completion_tokens}, "
                  f"total={breakdown.total_tokens}")


class GeminiAPIKernel:
    """Kernel with API-only token tracking (no estimation)."""
    
    def __init__(self, token_limit: int = 100000):
        self.budget = BudgetTracker(token_limit=token_limit)
        self.client = client
        self.model_name = 'gemini-2.0-flash-exp'
        self.conversation_history = []
    
    def inference(self, prompt: str, verbose: bool = True) -> Dict:
        """
        Make inference with real API token tracking.
        
        Raises:
            RuntimeError: If API doesn't provide token metadata
        """
        if verbose:
            print(f"\n[API] Sending: {prompt[:60]}...")
        
        # Call Gemini API
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )
        except Exception as e:
            raise RuntimeError(f"API call failed: {e}")
        
        # Extract token counts - FAIL if not available
        if not hasattr(response, 'usage_metadata'):
            raise RuntimeError(
                f"API response missing usage_metadata. "
                f"Cannot track tokens accurately. "
                f"This may indicate an API version issue or rate limiting."
            )
        
        # Get REAL token counts from API
        metadata = response.usage_metadata
        prompt_tokens = metadata.prompt_token_count
        completion_tokens = metadata.candidates_token_count
        total_tokens = metadata.total_token_count
        
        # Record in budget
        self.budget.record_inference(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            model=self.model_name
        )
        
        if verbose:
            print(f"[API] Response: {response.text[:80]}...")
            print(f"[API] Tokens: prompt={prompt_tokens}, completion={completion_tokens}, total={total_tokens}")
        
        return {
            'content': response.text,
            'tokens': {
                'prompt': prompt_tokens,
                'completion': completion_tokens,
                'total': total_tokens
            },
            'model': self.model_name,
            'source': 'real_api'  # Mark as real API count
        }
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass


def demo_basic_usage():
    """Demonstrate basic API-only token tracking."""
    print("\n" + "=" * 70)
    print("Basic API-Only Token Tracking")
    print("=" * 70)
    
    with GeminiAPIKernel(token_limit=100000) as kernel:
        tasks = [
            "What is 25 * 4?",
            "Explain in one sentence what a unikernel is.",
            "Count to 5.",
        ]
        
        for i, task in enumerate(tasks, 1):
            print(f"\n--- Task {i}/{len(tasks)} ---")
            print(f"Prompt: {task}")
            
            result = kernel.inference(task, verbose=True)
            
            # Show token breakdown
            tokens = result['tokens']
            print(f"Token Breakdown:")
            print(f"  Prompt:     {tokens['prompt']} tokens")
            print(f"  Completion: {tokens['completion']} tokens")
            print(f"  Total:      {tokens['total']} tokens")
            print(f"  Source:     {result['source']} (100% accurate)")
            
            time.sleep(0.5)
        
        print("\n" + "=" * 70)
        print("Final Budget Report")
        print("=" * 70)
        
        kernel.budget.print_status()
        kernel.budget.print_breakdown()


def demo_budget_limits():
    """Demonstrate budget limit enforcement."""
    print("\n" + "=" * 70)
    print("Budget Limit Enforcement")
    print("=" * 70)
    
    # Set a LOW limit to trigger warnings
    with GeminiAPIKernel(token_limit=200) as kernel:
        print(f"\n[+] Budget limit set to 200 tokens (intentionally low)")
        
        tasks = [
            "What is 2+2?",
            "What is 3+3?",
            "What is 4+4?",
        ]
        
        for i, task in enumerate(tasks, 1):
            print(f"\n--- Task {i}/{len(tasks)} ---")
            
            # Check budget before operation
            status = kernel.budget.get_status()
            if status.is_critical:
                print(f"[WARNING] Budget critical: {status.tokens_percent:.1f}% used")
                print(f"[WARNING] Only {status.tokens_remaining} tokens remaining")
                
                if status.tokens_remaining < 50:
                    print("[STOP] Insufficient budget - stopping execution")
                    break
            
            print(f"Prompt: {task}")
            result = kernel.inference(task, verbose=False)
            
            print(f"Response: {result['content'][:60]}...")
            print(f"Tokens used: {result['tokens']['total']}")
            print(f"Budget: {kernel.budget.status.tokens_used} / {kernel.budget.status.tokens_limit} "
                  f"({kernel.budget.status.tokens_percent:.1f}%)")
        
        print("\n" + "=" * 70)
        print("Final Status")
        print("=" * 70)
        kernel.budget.print_status()


def demo_token_optimization():
    """Demonstrate token usage analysis for optimization."""
    print("\n" + "=" * 70)
    print("Token Usage Analysis & Optimization")
    print("=" * 70)
    
    with GeminiAPIKernel(token_limit=100000) as kernel:
        # Compare different prompt styles
        prompts = [
            ("Verbose", "Please explain to me in detail what the result of multiplying 5 by 5 is and show your work"),
            ("Concise", "What is 5*5?"),
            ("System", "Calculate: 5*5"),
        ]
        
        print("\nComparing prompt efficiency:")
        
        for style, prompt in prompts:
            print(f"\n[{style} Prompt]")
            print(f"Prompt: {prompt}")
            
            result = kernel.inference(prompt, verbose=False)
            tokens = result['tokens']
            
            print(f"Response: {result['content'][:50]}...")
            print(f"Tokens: prompt={tokens['prompt']}, completion={tokens['completion']}, total={tokens['total']}")
            print(f"Efficiency: {len(result['content']) / tokens['total']:.2f} chars/token")
            
            time.sleep(0.3)
        
        print("\n" + "=" * 70)
        print("Token Usage Summary")
        print("=" * 70)
        kernel.budget.print_breakdown()
        
        print("\nOptimization Tips:")
        print("- Use concise prompts to reduce prompt tokens")
        print("- Request brief responses to reduce completion tokens")
        print("- Monitor token breakdown to identify inefficiencies")
        print("- All counts are 100% accurate from API metadata")


def main():
    """Main entry point."""
    print("\n" + "=" * 70)
    print("API-Only Budget Tracking Demo")
    print("=" * 70)
    print("\nThis example uses ONLY real API token counts.")
    print("No estimation or simulation - 100% accurate tracking.")
    print(f"\nAPI Key: {GEMINI_API_KEY[:20]}...")
    print(f"Model: gemini-2.0-flash-exp")
    print()
    
    try:
        # Run demonstrations
        demo_basic_usage()
        time.sleep(1)
        
        demo_budget_limits()
        time.sleep(1)
        
        demo_token_optimization()
        
        print("\n" + "=" * 70)
        print("Demo Complete")
        print("=" * 70)
        print("\nKey Takeaways:")
        print("- All token counts come from real API metadata")
        print("- 100% accurate - suitable for production billing")
        print("- Detailed breakdown helps optimize usage")
        print("- Budget limits enforce cost controls")
        print("- No estimation fallbacks - fail-fast if metadata missing")
        print()
        
        return 0
        
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
