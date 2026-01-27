#!/usr/bin/env python3
"""
Example 8: Budget Tracking and Monitoring

Demonstrates comprehensive budget tracking features including:
- Real-time budget status monitoring
- Historical consumption snapshots
- Detailed breakdown by operation type
- Burn rate calculation and remaining time estimation
- Critical budget alerts

This example works in both simulation and real kernel modes.
"""

import json
import time
import sys
from authority_nanos import AuthorityKernel


def demonstrate_basic_status():
    """Demonstrate basic budget status queries."""
    print("\n" + "=" * 70)
    print("Basic Budget Status")
    print("=" * 70)
    
    with AuthorityKernel() as ak:
        # Get current status
        status = ak.budget.get_status()
        
        print(f"\nTokens: {status.tokens_used:,} / {status.tokens_limit:,} ({status.tokens_percent:.1f}%)")
        print(f"Tool Calls: {status.tool_calls_used} / {status.tool_calls_limit} ({status.tool_calls_percent:.1f}%)")
        print(f"Wall Time: {status.wall_time_used} / {status.wall_time_limit} ({status.wall_time_percent:.1f}%)")
        print(f"Memory: {status.bytes_used / 1024 / 1024:.1f}MB / {status.bytes_limit / 1024 / 1024:.1f}MB ({status.bytes_percent:.1f}%)")
        
        # Check remaining resources
        print(f"\nRemaining:")
        print(f"  Tokens: {status.tokens_remaining:,}")
        print(f"  Tool Calls: {status.tool_calls_remaining}")
        
        # Check if critical
        if status.is_any_critical:
            print("\nWARNING: Budget is critically low")
        else:
            print("\nStatus: Budget is healthy")


def demonstrate_formatted_output():
    """Demonstrate formatted budget output with progress bars."""
    print("\n" + "=" * 70)
    print("Formatted Budget Display")
    print("=" * 70)
    
    with AuthorityKernel() as ak:
        # Perform some operations to consume budget
        print("\nPerforming operations...")
        
        # Allocate some objects
        for i in range(5):
            data = json.dumps({"index": i, "value": i * 10}).encode()
            handle = ak.alloc(f"item_{i}", data)
        
        # Call a simulated tool
        try:
            ak.call_tool("test_tool", {"param": "value"})
        except:
            pass
        
        # Show formatted status
        ak.budget.print_status(detailed=False)


def demonstrate_historical_tracking():
    """Demonstrate historical budget snapshots."""
    print("\n" + "=" * 70)
    print("Historical Budget Tracking")
    print("=" * 70)
    
    with AuthorityKernel() as ak:
        print("\nPerforming operations over time...")
        
        # Perform operations with delays to create history
        for i in range(3):
            print(f"  Iteration {i + 1}...")
            
            # Allocate objects
            for j in range(2):
                data = json.dumps({"iter": i, "item": j}).encode()
                handle = ak.alloc(f"hist_{i}_{j}", data)
            
            # Small delay
            time.sleep(0.1)
        
        # Get historical snapshots
        history = ak.budget.get_history(count=10)
        
        print(f"\nRetrieved {len(history)} historical snapshots:")
        print("\nTimestamp                    Tokens    Tool Calls    Wall Time (ms)")
        print("-" * 70)
        
        for snapshot in history:
            timestamp_str = snapshot.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            print(f"{timestamp_str}    {snapshot.tokens:6d}    {snapshot.tool_calls:10d}    {snapshot.wall_time_ms:14d}")


def demonstrate_detailed_breakdown():
    """Demonstrate detailed budget breakdown."""
    print("\n" + "=" * 70)
    print("Detailed Budget Breakdown")
    print("=" * 70)
    
    with AuthorityKernel() as ak:
        print("\nPerforming various operations...")
        
        # Mix of different operations
        for i in range(3):
            # Heap operations
            data = json.dumps({"type": "data", "index": i}).encode()
            handle = ak.alloc(f"breakdown_{i}", data)
            
            # Tool calls (simulated)
            try:
                ak.call_tool(f"tool_{i % 2}", {"param": i})
            except:
                pass
        
        # Get detailed breakdown
        breakdown = ak.budget.get_breakdown()
        
        print("\nToken Consumption by Operation:")
        for operation, tokens in breakdown.tokens_by_operation.items():
            print(f"  {operation}: {tokens:,} tokens")
        
        print("\nTool Calls by Name:")
        if breakdown.tool_calls_by_name:
            for tool, calls in breakdown.tool_calls_by_name.items():
                print(f"  {tool}: {calls} calls")
        else:
            print("  (No tool calls recorded)")
        
        # Show top consumers
        print("\nTop Token Consumers:")
        for operation, tokens in breakdown.top_token_consumers(3):
            print(f"  {operation}: {tokens:,} tokens")


def demonstrate_burn_rate_estimation():
    """Demonstrate burn rate calculation and remaining time estimation."""
    print("\n" + "=" * 70)
    print("Burn Rate and Time Estimation")
    print("=" * 70)
    
    with AuthorityKernel() as ak:
        print("\nGenerating consumption history...")
        
        # Perform operations to create consumption pattern
        for i in range(5):
            for j in range(3):
                data = json.dumps({"batch": i, "item": j}).encode()
                handle = ak.alloc(f"rate_{i}_{j}", data)
            time.sleep(0.05)
        
        # Estimate remaining runtime
        remaining = ak.budget.estimate_remaining_runtime()
        
        if remaining:
            if remaining == time.timedelta.max:
                print("\nEstimated remaining time: Unlimited (no consumption detected)")
            else:
                print(f"\nEstimated remaining time: ~{str(remaining).split('.')[0]}")
                print("(Based on current consumption rate)")
        else:
            print("\nCannot estimate remaining time (insufficient history)")


def demonstrate_monitoring_loop():
    """Demonstrate continuous budget monitoring."""
    print("\n" + "=" * 70)
    print("Continuous Budget Monitoring")
    print("=" * 70)
    
    with AuthorityKernel() as ak:
        print("\nMonitoring budget for 3 seconds...")
        print("(Performing operations in background)")
        
        start_time = time.time()
        iteration = 0
        
        while time.time() - start_time < 3.0:
            # Perform some operations
            data = json.dumps({"monitor": iteration}).encode()
            handle = ak.alloc(f"monitor_{iteration}", data)
            
            # Check status
            status = ak.budget.get_status(force_refresh=True)
            
            # Alert if critical
            if status.is_any_critical:
                print(f"\n[{time.time() - start_time:.1f}s] ALERT: Budget critical")
                print(f"  Tokens: {status.tokens_percent:.1f}%")
                print(f"  Tool Calls: {status.tool_calls_percent:.1f}%")
            
            iteration += 1
            time.sleep(0.2)
        
        print(f"\nCompleted {iteration} iterations")
        print("\nFinal status:")
        ak.budget.print_status(detailed=True)


def main():
    """Main entry point."""
    print("\n" + "=" * 70)
    print("Budget Tracking Example")
    print("=" * 70)
    print("\nThis example demonstrates comprehensive budget tracking features.")
    print("All examples work in simulation mode (no kernel build required).")
    
    try:
        # Run demonstrations
        demonstrate_basic_status()
        demonstrate_formatted_output()
        demonstrate_historical_tracking()
        demonstrate_detailed_breakdown()
        demonstrate_burn_rate_estimation()
        demonstrate_monitoring_loop()
        
        print("\n" + "=" * 70)
        print("Budget Tracking Example Complete")
        print("=" * 70)
        print("\nKey Takeaways:")
        print("- Budget tracking provides real-time visibility into resource consumption")
        print("- Historical snapshots enable trend analysis and burn rate calculation")
        print("- Detailed breakdowns help identify resource-intensive operations")
        print("- Continuous monitoring enables proactive budget management")
        print()
        
        return 0
        
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
