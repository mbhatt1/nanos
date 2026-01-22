#!/bin/bash
# Helper script to run Authority Nanos SDK examples
#
# By default, examples run in SIMULATION mode - no kernel required!
# Use --real flag to run against the actual Authority Kernel.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Parse arguments
EXAMPLE_NUM=""
REAL_MODE=""
EXTRA_ARGS=""

for arg in "$@"; do
    case "$arg" in
        --real|--kernel)
            REAL_MODE="--real"
            ;;
        all)
            EXAMPLE_NUM="all"
            ;;
        [0-9]|[0-9][0-9])
            EXAMPLE_NUM="$arg"
            ;;
        *)
            EXTRA_ARGS="$EXTRA_ARGS $arg"
            ;;
    esac
done

# Show usage if no example specified
if [ -z "$EXAMPLE_NUM" ]; then
    echo "Authority Nanos SDK Examples"
    echo ""
    echo "Usage: $0 <example_number|all> [--real]"
    echo ""
    echo "Options:"
    echo "  --real, --kernel   Run with real kernel (default: simulation mode)"
    echo ""
    echo "Available examples:"
    for i in 0 1 2 3 4 5; do
        EXAMPLE="$SCRIPT_DIR/0${i}_*.py"
        if ls $EXAMPLE >/dev/null 2>&1; then
            NAME=$(basename $EXAMPLE | sed 's/0[0-9]_//;s/.py//;s/_/ /g')
            echo "  $i) $NAME"
        fi
    done
    echo ""
    echo "Examples (simulation mode - works out of the box):"
    echo "  $0 0           # Run hello world example"
    echo "  $0 1           # Run heap operations example"
    echo "  $0 all         # Run all examples"
    echo ""
    echo "Examples (real kernel mode):"
    echo "  $0 1 --real    # Run heap operations with real kernel"
    exit 1
fi

# Function to run a single example
run_example() {
    local num="$1"
    local example_file

    # Find the example file
    example_file=$(ls "$SCRIPT_DIR"/${num}_*.py 2>/dev/null | head -1)

    if [ -z "$example_file" ] || [ ! -f "$example_file" ]; then
        echo "[-] Example $num not found"
        return 1
    fi

    local name=$(basename "$example_file")
    local mode="SIMULATION"
    [ -n "$REAL_MODE" ] && mode="REAL KERNEL"

    echo ""
    echo "========================================"
    echo "Running: $name ($mode mode)"
    echo "========================================"
    echo ""

    # Set up library path for real kernel mode
    if [ -n "$REAL_MODE" ]; then
        # Try to find libak
        for libpath in \
            "$PROJECT_ROOT/output/platform/pc/lib" \
            "$PROJECT_ROOT/output/platform/virt/lib" \
            "/usr/local/lib" \
            "/usr/lib"
        do
            if [ -f "$libpath/libak.so" ] || [ -f "$libpath/libak.dylib" ]; then
                export LD_LIBRARY_PATH="$libpath:$LD_LIBRARY_PATH"
                export DYLD_LIBRARY_PATH="$libpath:$DYLD_LIBRARY_PATH"
                break
            fi
        done
    fi

    # Run the example
    python3 "$example_file" $REAL_MODE $EXTRA_ARGS
}

# Run examples
if [ "$EXAMPLE_NUM" = "all" ]; then
    echo "Running all examples..."
    for i in 0 1 2 3 4 5; do
        example_file=$(ls "$SCRIPT_DIR"/0${i}_*.py 2>/dev/null | head -1)
        if [ -n "$example_file" ] && [ -f "$example_file" ]; then
            run_example "0$i"
            echo ""
        fi
    done
    echo ""
    echo "========================================"
    echo "All examples completed!"
    echo "========================================"
else
    # Format example number with leading zero if needed
    EXAMPLE_PADDED=$(printf "%02d" "$EXAMPLE_NUM")
    run_example "$EXAMPLE_PADDED"
fi
