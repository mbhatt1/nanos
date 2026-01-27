#!/usr/bin/env python3
"""
Example 01: Universal Budget Tracking (All LLM APIs)

Production-grade token tracking that works with ANY LLM provider:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- Google Gemini
- Auto-detects available provider

Features:
- 100% accurate token counts from API metadata
- NO estimation fallbacks
- Fail-fast if API metadata unavailable
- Works with any supported LLM provider
- Detailed token breakdown (prompt vs completion)

Setup:
1. Install provider SDK:
   pip install openai          # For OpenAI
   pip install anthropic        # For Anthropic
   pip install google-genai     # For Gemini

2. Set API key (any one):
   export OPENAI_API_KEY=your_key
   export ANTHROPIC_API_KEY=your_key
   export GEMINI_API_KEY=your_key

3. Run:
   python3 examples/01_budget_tracking_unified.py
"""

import sys
import os
import time
from typing import Optional
from datetime import datetime, timedelta
from dataclasses import dataclass

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Import Authority Nanos adapters
try:
    from authority_nanos.llm_adapters import (
        get_adapter,
        list_available_providers,
        LLMAdapter,
        TokenUsage,
        LLMResponse
    )
except ImportError:
    print("ERROR: authority_nanos package not found")
    print("Install with: cd sdk/python && pip install -e .")
    sys.exit(1)


@dataclass
class BudgetStatus:
    """Budget status tracking."""
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


class UniversalBudgetTracker:
    """Budget tracker that works with any LLM provider."""
    
    def __init__(self, llm_adapter: LLMAdapter, token_limit: int = 100000):
        self.adapter = llm_adapter
        self.status = BudgetStatus(
            tokens_used=0,
            tokens_limit=token_limit,
            tool_calls_used=0,
            tool_calls_limit=50,
            wall_time_used=0,
            wall_time_limit=300000
        )
        self.start_time = datetime.now()
        self.history = []
        
        print(f"[+] Budget tracker initialized")
        print(f"    Provider: {llm_adapter.provider_name}")
        print(f"    Model: {llm_adapter.model}")
        print(f"    Token Limit: {token_limit:,}")
    
    def generate(self, prompt: str, verbose: bool = True) -> LLMResponse:
        """Generate with token tracking."""
        if verbose:
            print(f"\n[{self.adapter.provider_name}] Prompt: {prompt[:60]}...")
        
        # Check budget before call
        if self.status.tokens_percent >= 100:
            raise RuntimeError("Budget exhausted - cannot make more API calls")
        
        # Generate
        response = self.adapter.generate(prompt)
        
        # Record usage
        self.status.tokens_used += response.usage.total_tokens
        self.history.append({
            'timestamp': datetime.now(),
            'usage': response.usage,
            'prompt': prompt[:50]
        })
        
        # Update wall time
        elapsed = (datetime.now() - self.start_time).total_seconds()
        self.status.wall_time_used = int(elapsed * 1000)
        
        if verbose:
            print(f"[{self.adapter.provider_name}] Response: {response.content[:60]}...")
            print(f"[{self.adapter.provider_name}] Tokens: "
                  f"prompt={response.usage.prompt_tokens}, "
                  f"completion={response.usage.completion_tokens}, "
                  f"total={response.usage.total_tokens}")
            print(f"[Budget] {self.status.tokens_used:,} / {self.status.tokens_limit:,} "
                  f"({self.status.tokens_percent:.1f}%)")
        
        return response
    
    def print_status(self):
        """Print budget status."""
        s = self.status
        print(f"\nBudget Status:")
        print(f"  Provider:   {self.adapter.provider_name}")
        print(f"  Model:      {self.adapter.model}")
        print(f"  Tokens:     {s.tokens_used:,} / {s.tokens_limit:,} ({s.tokens_percent:.1f}%)")
        print(f"  Remaining:  {s.tokens_remaining:,}")
        print(f"  Wall Time:  {s.wall_time_used/1000:.1f}s")
        print(f"  Status:     {'CRITICAL' if s.is_critical else 'OK'}")
    
    def print_breakdown(self):
        """Print detailed breakdown."""
        if not self.history:
            print("\nNo history available")
            return
        
        print(f"\nToken Usage Breakdown:")
        print(f"  Total Calls: {len(self.history)}")
        
        total_prompt = sum(h['usage'].prompt_tokens for h in self.history)
        total_completion = sum(h['usage'].completion_tokens for h in self.history)
        
        print(f"  Prompt Tokens:     {total_prompt:,}")
        print(f"  Completion Tokens: {total_completion:,}")
        print(f"  Total Tokens:      {self.status.tokens_used:,}")
        
        print(f"\nRecent Calls:")
        for entry in self.history[-5:]:
            time_str = entry['timestamp'].strftime("%H:%M:%S")
            usage = entry['usage']
            print(f"  [{time_str}] {entry['prompt'][:40]}... "
                  f"(prompt={usage.prompt_tokens}, "
                  f"completion={usage.completion_tokens}, "
                  f"total={usage.total_tokens})")


def demo_basic_usage(tracker: UniversalBudgetTracker):
    """Basic usage demonstration."""
    print("\n" + "=" * 70)
    print("Basic Usage Demo")
    print("=" * 70)
    
    tasks = [
        "What is 25 * 4?",
        "Explain in one sentence what a unikernel is.",
        "Count to 5.",
    ]
    
    for i, task in enumerate(tasks, 1):
        print(f"\n--- Task {i}/{len(tasks)} ---")
        response = tracker.generate(task, verbose=True)
        time.sleep(0.3)
    
    tracker.print_status()
    tracker.print_breakdown()


def demo_budget_enforcement(tracker: UniversalBudgetTracker):
    """Budget limit enforcement demo."""
    print("\n" + "=" * 70)
    print("Budget Enforcement Demo")
    print("=" * 70)
    
    # Create tracker with LOW limit
    low_limit_tracker = UniversalBudgetTracker(tracker.adapter, token_limit=200)
    
    tasks = [
        "What is 2+2?",
        "What is 3+3?",
        "What is 4+4?",
        "What is 5+5?",
    ]
    
    for i, task in enumerate(tasks, 1):
        print(f"\n--- Task {i}/{len(tasks)} ---")
        
        if low_limit_tracker.status.is_critical:
            print(f"[WARNING] Budget critical: {low_limit_tracker.status.tokens_percent:.1f}%")
            if low_limit_tracker.status.tokens_remaining < 30:
                print("[STOP] Insufficient budget remaining")
                break
        
        try:
            low_limit_tracker.generate(task, verbose=False)
            print(f"Response received. Budget: {low_limit_tracker.status.tokens_percent:.1f}%")
        except RuntimeError as e:
            print(f"[ERROR] {e}")
            break
    
    low_limit_tracker.print_status()


def demo_optimization(tracker: UniversalBudgetTracker):
    """Token optimization comparison."""
    print("\n" + "=" * 70)
    print("Token Optimization Demo")
    print("=" * 70)
    
    prompts = [
        ("Verbose", "Please explain to me in detail what the result of multiplying 5 by 5 is"),
        ("Concise", "What is 5*5?"),
        ("System", "Calculate: 5*5"),
    ]
    
    print("\nComparing prompt efficiency:")
    
    results = []
    for style, prompt in prompts:
        print(f"\n[{style} Prompt]")
        print(f"Prompt: {prompt}")
        
        response = tracker.generate(prompt, verbose=False)
        usage = response.usage
        efficiency = len(response.content) / usage.total_tokens
        
        print(f"Response: {response.content[:50]}...")
        print(f"Tokens: prompt={usage.prompt_tokens}, "
              f"completion={usage.completion_tokens}, "
              f"total={usage.total_tokens}")
        print(f"Efficiency: {efficiency:.2f} chars/token")
        
        results.append((style, usage.total_tokens))
        time.sleep(0.3)
    
    print(f"\n" + "=" * 40)
    print("Optimization Summary:")
    best = min(results, key=lambda x: x[1])
    for style, tokens in results:
        indicator = " <- Most efficient" if (style, tokens) == best else ""
        print(f"  {style}: {tokens} tokens{indicator}")


def main():
    """Main entry point."""
    print("\n" + "=" * 70)
    print("Universal Budget Tracking Demo")
    print("=" * 70)
    print("\nSupports: OpenAI, Anthropic (Claude), Google Gemini")
    print("Auto-detects available provider from environment variables")
    print()
    
    # Check available providers
    available = list_available_providers()
    
    if not available:
        print("ERROR: No LLM provider found")
        print("\nPlease set one of:")
        print("  export OPENAI_API_KEY=your_key")
        print("  export ANTHROPIC_API_KEY=your_key")
        print("  export GEMINI_API_KEY=your_key")
        print("\nAnd install the SDK:")
        print("  pip install openai          # For OpenAI")
        print("  pip install anthropic        # For Anthropic")
        print("  pip install google-genai     # For Gemini")
        return 1
    
    print(f"Available providers: {', '.join(available)}")
    
    # Get adapter (auto-detect or specify)
    adapter = get_adapter()  # or get_adapter('OpenAI') to prefer specific
    
    if not adapter:
        print("ERROR: Failed to create adapter")
        return 1
    
    print(f"\nUsing: {adapter.provider_name} with {adapter.model}")
    print()
    
    try:
        # Create tracker
        tracker = UniversalBudgetTracker(adapter, token_limit=100000)
        
        # Run demos
        demo_basic_usage(tracker)
        time.sleep(1)
        
        demo_budget_enforcement(tracker)
        time.sleep(1)
        
        demo_optimization(tracker)
        
        print("\n" + "=" * 70)
        print("Demo Complete")
        print("=" * 70)
        print("\nKey Points:")
        print(f"- Provider: {adapter.provider_name}")
        print("- All token counts are 100% accurate from API metadata")
        print("- No estimation fallbacks")
        print("- Works with any supported LLM provider")
        print("- Production-ready for billing and cost control")
        print()
        
        return 0
        
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
