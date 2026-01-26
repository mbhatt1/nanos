"""
Authority Nanos - Budget Tracking Module.

This module provides comprehensive budget tracking and monitoring for resource consumption
in Authority Kernel operations. Track tokens, tool calls, wall time, and memory usage with
historical snapshots and detailed breakdowns.

Example:
    from authority_nanos import AuthorityKernel
    
    with AuthorityKernel() as ak:
        # Get current status
        status = ak.budget.get_status()
        print(f"Tokens used: {status.tokens_used} / {status.tokens_limit}")
        
        # Print formatted status
        ak.budget.print_status(detailed=True)
        
        # Get historical data
        history = ak.budget.get_history(count=10)
        for snapshot in history:
            print(f"{snapshot.timestamp}: {snapshot.tokens} tokens")
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import json


@dataclass
class BudgetStatus:
    """
    Current budget consumption status.
    
    Attributes:
        tokens_used: Total tokens consumed (input + output)
        tokens_limit: Total token limit
        tokens_percent: Percentage of tokens consumed
        tool_calls_used: Number of tool calls made
        tool_calls_limit: Tool call limit
        tool_calls_percent: Percentage of tool calls used
        wall_time_used: Wall time elapsed
        wall_time_limit: Wall time limit
        wall_time_percent: Percentage of wall time used
        bytes_used: Total bytes consumed
        bytes_limit: Byte limit
        bytes_percent: Percentage of bytes used
        last_updated: When this status was captured
    """
    tokens_used: int
    tokens_limit: int
    tokens_percent: float
    
    tool_calls_used: int
    tool_calls_limit: int
    tool_calls_percent: float
    
    wall_time_used: timedelta
    wall_time_limit: timedelta
    wall_time_percent: float
    
    bytes_used: int
    bytes_limit: int
    bytes_percent: float
    
    last_updated: datetime
    
    @property
    def tokens_remaining(self) -> int:
        """Tokens remaining before hitting limit."""
        return max(0, self.tokens_limit - self.tokens_used)
    
    @property
    def tool_calls_remaining(self) -> int:
        """Tool calls remaining before hitting limit."""
        return max(0, self.tool_calls_limit - self.tool_calls_used)
    
    @property
    def is_tokens_critical(self) -> bool:
        """Returns True if tokens > 90% used."""
        return self.tokens_percent > 90.0
    
    @property
    def is_tool_calls_critical(self) -> bool:
        """Returns True if tool calls > 90% used."""
        return self.tool_calls_percent > 90.0
    
    @property
    def is_time_critical(self) -> bool:
        """Returns True if wall time > 90% used."""
        return self.wall_time_percent > 90.0
    
    @property
    def is_any_critical(self) -> bool:
        """Returns True if any budget > 90% used."""
        return (self.tokens_percent > 90.0 or
                self.tool_calls_percent > 90.0 or
                self.wall_time_percent > 90.0 or
                self.bytes_percent > 90.0)


@dataclass
class BudgetSnapshot:
    """
    Historical budget snapshot at a point in time.
    
    Attributes:
        timestamp: When this snapshot was taken
        tokens: Total tokens at this time
        tool_calls: Total tool calls at this time
        wall_time_ms: Wall time elapsed (milliseconds)
        bytes: Total bytes consumed
    """
    timestamp: datetime
    tokens: int
    tool_calls: int
    wall_time_ms: int
    bytes: int


@dataclass
class BudgetBreakdown:
    """
    Detailed breakdown of budget consumption by operation type.
    
    Attributes:
        tokens_by_model: Token consumption per model
        tokens_by_operation: Token consumption per operation type
        tool_calls_by_name: Tool call count per tool name
    """
    tokens_by_model: Dict[str, int]
    tokens_by_operation: Dict[str, int]
    tool_calls_by_name: Dict[str, int]
    
    def top_token_consumers(self, n: int = 5) -> List[tuple]:
        """Get top N token-consuming operations."""
        items = sorted(self.tokens_by_operation.items(), 
                      key=lambda x: x[1], reverse=True)
        return items[:n]
    
    def top_tools(self, n: int = 5) -> List[tuple]:
        """Get top N most-called tools."""
        items = sorted(self.tool_calls_by_name.items(),
                      key=lambda x: x[1], reverse=True)
        return items[:n]


class BudgetTracker:
    """
    Budget consumption tracking interface.
    
    This class provides methods to query current budget status, retrieve
    historical consumption data, and monitor resource usage patterns.
    
    The tracker maintains a cache with a 1-second TTL to reduce kernel syscall
    overhead when querying status repeatedly.
    """
    
    def __init__(self, kernel):
        """
        Initialize budget tracker.
        
        Args:
            kernel: AuthorityKernel instance
        """
        self.kernel = kernel
        self._cached_status: Optional[BudgetStatus] = None
        self._cache_time: Optional[datetime] = None
        self._cache_ttl = timedelta(seconds=1)
    
    def get_status(self, force_refresh: bool = False) -> BudgetStatus:
        """
        Get current budget status.
        
        Args:
            force_refresh: Force refresh from kernel (bypass cache)
            
        Returns:
            BudgetStatus with current consumption
            
        Raises:
            AuthorityKernelError: If kernel operation fails
        """
        now = datetime.now()
        
        # Use cache if valid
        if (not force_refresh and 
            self._cached_status and 
            self._cache_time and
            now - self._cache_time < self._cache_ttl):
            return self._cached_status
        
        # Call kernel syscall 1038 (AK_SYS_BUDGET_STATUS)
        result = self.kernel.syscall(1038)
        data = json.loads(result.decode('utf-8'))
        
        status = BudgetStatus(
            tokens_used=data['tokens_used'],
            tokens_limit=data['tokens_limit'],
            tokens_percent=data['tokens_used'] / data['tokens_limit'] * 100 
                if data['tokens_limit'] > 0 else 0,
            
            tool_calls_used=data['tool_calls_used'],
            tool_calls_limit=data['tool_calls_limit'],
            tool_calls_percent=data['tool_calls_used'] / data['tool_calls_limit'] * 100
                if data['tool_calls_limit'] > 0 else 0,
            
            wall_time_used=timedelta(milliseconds=data['wall_time_ms_used']),
            wall_time_limit=timedelta(milliseconds=data['wall_time_ms_limit']),
            wall_time_percent=data['wall_time_ms_used'] / data['wall_time_ms_limit'] * 100
                if data['wall_time_ms_limit'] > 0 else 0,
            
            bytes_used=data['bytes_used'],
            bytes_limit=data['bytes_limit'],
            bytes_percent=data['bytes_used'] / data['bytes_limit'] * 100
                if data['bytes_limit'] > 0 else 0,
            
            last_updated=datetime.fromtimestamp(data['last_update_ms'] / 1000)
        )
        
        # Update cache
        self._cached_status = status
        self._cache_time = now
        
        return status
    
    def get_history(self, count: int = 60) -> List[BudgetSnapshot]:
        """
        Get historical budget snapshots.
        
        Args:
            count: Number of snapshots to retrieve (max 60)
            
        Returns:
            List of BudgetSnapshot in chronological order
            
        Raises:
            AuthorityKernelError: If kernel operation fails
        """
        if count > 60:
            count = 60
        
        # Call kernel syscall 1039 (AK_SYS_BUDGET_HISTORY) with count parameter
        request_data = json.dumps({"count": count}).encode('utf-8')
        result = self.kernel.syscall(1039, request_data)
        data = json.loads(result.decode('utf-8'))
        
        snapshots = []
        for item in data['snapshots']:
            snapshots.append(BudgetSnapshot(
                timestamp=datetime.fromtimestamp(item['timestamp_ms'] / 1000),
                tokens=item['tokens'],
                tool_calls=item['tool_calls'],
                wall_time_ms=item['wall_time_ms'],
                bytes=item['bytes']
            ))
        
        return snapshots
    
    def get_breakdown(self) -> BudgetBreakdown:
        """
        Get detailed breakdown of budget consumption.
        
        Returns:
            BudgetBreakdown with per-operation details
            
        Raises:
            AuthorityKernelError: If kernel operation fails
        """
        # Call kernel syscall 1040 (AK_SYS_BUDGET_BREAKDOWN)
        result = self.kernel.syscall(1040)
        data = json.loads(result.decode('utf-8'))
        
        return BudgetBreakdown(
            tokens_by_model=data.get('tokens_by_model', {}),
            tokens_by_operation=data.get('tokens_by_operation', {}),
            tool_calls_by_name=data.get('tool_calls_by_name', {})
        )
    
    def estimate_remaining_runtime(self) -> Optional[timedelta]:
        """
        Estimate how much time remains based on current burn rate.
        
        Returns:
            Estimated remaining time, or None if cannot estimate
        """
        history = self.get_history(count=10)
        if len(history) < 2:
            return None
        
        # Calculate burn rate (tokens per second)
        time_span = (history[-1].timestamp - history[0].timestamp).total_seconds()
        if time_span == 0:
            return None
        
        tokens_consumed = history[-1].tokens - history[0].tokens
        burn_rate = tokens_consumed / time_span
        
        if burn_rate == 0:
            return timedelta.max
        
        status = self.get_status()
        remaining_tokens = status.tokens_remaining
        remaining_seconds = remaining_tokens / burn_rate
        
        return timedelta(seconds=remaining_seconds)
    
    def print_status(self, detailed: bool = False):
        """
        Print budget status to console with formatted progress bars.
        
        Args:
            detailed: Include detailed breakdown and estimates
        """
        status = self.get_status()
        
        print("\n" + "=" * 60)
        print("Budget Consumption Status")
        print("=" * 60)
        
        # Tokens
        bar = self._progress_bar(status.tokens_percent)
        print(f"Tokens:     {bar} {status.tokens_used:,} / {status.tokens_limit:,} ({status.tokens_percent:.1f}%)")
        
        # Tool calls
        bar = self._progress_bar(status.tool_calls_percent)
        print(f"Tool Calls: {bar} {status.tool_calls_used} / {status.tool_calls_limit} ({status.tool_calls_percent:.1f}%)")
        
        # Wall time
        bar = self._progress_bar(status.wall_time_percent)
        wall_used = str(status.wall_time_used).split('.')[0]
        wall_limit = str(status.wall_time_limit).split('.')[0]
        print(f"Wall Time:  {bar} {wall_used} / {wall_limit} ({status.wall_time_percent:.1f}%)")
        
        # Bytes
        bar = self._progress_bar(status.bytes_percent)
        bytes_used_mb = status.bytes_used / 1024 / 1024
        bytes_limit_mb = status.bytes_limit / 1024 / 1024
        print(f"Memory:     {bar} {bytes_used_mb:.1f}MB / {bytes_limit_mb:.1f}MB ({status.bytes_percent:.1f}%)")
        
        # Warnings
        if status.is_any_critical:
            print("\nWARNING: Budget critically low")
            if status.is_tokens_critical:
                print(f"   - Tokens: Only {status.tokens_remaining:,} remaining")
            if status.is_tool_calls_critical:
                print(f"   - Tool Calls: Only {status.tool_calls_remaining} remaining")
            if status.is_time_critical:
                remaining = status.wall_time_limit - status.wall_time_used
                print(f"   - Time: Only {str(remaining).split('.')[0]} remaining")
        
        # Detailed information
        if detailed:
            print("\n" + "-" * 60)
            remaining = self.estimate_remaining_runtime()
            if remaining:
                if remaining == timedelta.max:
                    print("Estimated remaining: Unlimited (no consumption)")
                else:
                    print(f"Estimated remaining: ~{str(remaining).split('.')[0]}")
            
            breakdown = self.get_breakdown()
            if breakdown.tokens_by_operation:
                print("\nTop Token Consumers:")
                for op, tokens in breakdown.top_token_consumers(3):
                    print(f"  - {op}: {tokens:,} tokens")
            
            if breakdown.tool_calls_by_name:
                print("\nTop Tools:")
                for tool, calls in breakdown.top_tools(3):
                    print(f"  - {tool}: {calls} calls")
        
        print("=" * 60 + "\n")
    
    def _progress_bar(self, percent: float, width: int = 20) -> str:
        """Generate a visual progress bar."""
        filled = int(width * percent / 100)
        empty = width - filled
        
        if percent > 90:
            color = '\033[91m'  # Red
        elif percent > 75:
            color = '\033[93m'  # Yellow
        else:
            color = '\033[92m'  # Green
        
        reset = '\033[0m'
        bar_filled = '█' * filled
        bar_empty = '░' * empty
        return f"{color}[{bar_filled}{bar_empty}]{reset}"
