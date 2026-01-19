"""
Platform detection and binary loader module for the Authority Nanos SDK.

This module provides functionality to detect the current platform, locate the libak
binary (either bundled in the wheel or installed system-wide), and load it. It implements
a comprehensive search strategy with multiple fallback locations and provides detailed
error messages when the binary cannot be found.

The module uses a thread-safe caching mechanism to avoid repeated searches after the
first successful discovery.
"""

import logging
import os
import sys
import threading
from pathlib import Path
from typing import List, Optional

from authority_nanos.exceptions import AKError

logger = logging.getLogger(__name__)

# Error code for binary loader errors
ERROR_CODE_LIBAK_NOT_FOUND = "AK_ERR_LIBAK_NOT_FOUND"


class LibakNotFoundError(AKError):
    """
    Raised when the libak binary cannot be found or loaded.

    This exception is raised when the SDK cannot locate the libak binary after
    searching all configured locations. It provides detailed information about
    the search paths attempted and suggestions for resolving the issue.
    """

    def __init__(
        self,
        message: str,
        search_paths: Optional[List[str]] = None,
        platform: Optional[str] = None,
        suggestion: Optional[str] = None,
    ) -> None:
        """
        Initialize a LibakNotFoundError instance.

        Args:
            message: A human-readable description of the error
            search_paths: List of paths that were searched
            platform: The platform identifier (e.g., 'macos_x86_64')
            suggestion: A suggested action to resolve the error
        """
        context = {"platform": platform} if platform else {}
        if search_paths:
            context["search_paths"] = search_paths

        default_suggestion = suggestion or (
            "Try one of the following:\n"
            "  1. Install from pip: pip install authority-nanos\n"
            "  2. Build from source: pip install -e .\n"
            "  3. Set LIBAK_PATH environment variable to the libak binary location\n"
            "  4. Place libak binary in the current directory"
        )

        super().__init__(
            message,
            code=ERROR_CODE_LIBAK_NOT_FOUND,
            context=context,
            suggestion=default_suggestion,
        )
        self.search_paths = search_paths or []
        self.platform = platform


def get_platform_tag() -> str:
    """
    Return platform identifier for the current system.

    Returns a standardized platform tag used to locate the correct binary for
    the running platform. Supports macOS (x86_64 and ARM64) and Linux
    (x86_64 and ARM64).

    Returns:
        Platform identifier string: 'macos_x86_64', 'macos_arm64',
        'linux_x86_64', or 'linux_arm64'

    Raises:
        LibakNotFoundError: If the platform is not supported
    """
    system = sys.platform.lower()
    machine = platform_machine()

    if system == "darwin":
        if machine in ("x86_64", "AMD64"):
            return "macos_x86_64"
        elif machine in ("arm64", "aarch64"):
            return "macos_arm64"
        else:
            raise LibakNotFoundError(
                f"Unsupported macOS architecture: {machine}",
                platform=f"darwin/{machine}",
                suggestion="Authority Nanos only supports macOS x86_64 and ARM64 architectures.",
            )
    elif system == "linux":
        if machine in ("x86_64", "AMD64"):
            return "linux_x86_64"
        elif machine in ("arm64", "aarch64"):
            return "linux_arm64"
        else:
            raise LibakNotFoundError(
                f"Unsupported Linux architecture: {machine}",
                platform=f"linux/{machine}",
                suggestion="Authority Nanos only supports Linux x86_64 and ARM64 architectures.",
            )
    else:
        raise LibakNotFoundError(
            f"Unsupported platform: {system}",
            platform=system,
            suggestion="Authority Nanos only supports macOS and Linux platforms.",
        )


def platform_machine() -> str:
    """
    Return the machine architecture.

    This is a wrapper around platform.machine() that can be mocked in tests.

    Returns:
        Machine architecture string
    """
    import platform

    return platform.machine()


def get_libak_filename() -> str:
    """
    Return library filename for the current platform.

    Returns the appropriate filename (with extension) for the libak binary
    on the current platform.

    Returns:
        Library filename: 'libak.dylib' for macOS or 'libak.so' for Linux
    """
    system = sys.platform.lower()
    if system == "darwin":
        return "libak.dylib"
    elif system == "linux":
        return "libak.so"
    else:
        # Fallback - shouldn't reach here if get_platform_tag() was called
        return "libak.so"


class LibakBinaryLocator:
    """
    Locates and caches the path to the libak binary.

    This class implements a comprehensive search strategy for finding the libak
    binary with multiple fallback locations. It provides thread-safe caching
    to avoid repeated searches after the first successful discovery.

    The search order is:
    1. Bundled in wheel: {package_dir}/_libak/libak.{so|dylib}
    2. System libraries: /usr/local/lib, /usr/lib (Linux), /opt/local/lib (macOS)
    3. Environment variable: LIBAK_PATH
    4. Current directory: ./libak.{so|dylib}

    Attributes:
        _cached_path: The cached path to the libak binary
        _cache_lock: Thread lock for thread-safe caching
    """

    _cached_path: Optional[str] = None
    _cache_lock = threading.Lock()

    @classmethod
    def find(cls) -> str:
        """
        Find and return the path to the libak binary.

        Searches for the libak binary using a multi-stage fallback strategy:
        1. Returns cached path if available
        2. Searches bundled locations in the package
        3. Searches system library paths
        4. Checks environment variable LIBAK_PATH
        5. Searches current directory

        Returns:
            Absolute path to the libak binary

        Raises:
            LibakNotFoundError: If the binary cannot be found in any location
        """
        # Check cache first
        if cls._cached_path is not None:
            logger.debug(f"Using cached libak path: {cls._cached_path}")
            return cls._cached_path

        with cls._cache_lock:
            # Double-check pattern after acquiring lock
            if cls._cached_path is not None:
                return cls._cached_path

            # Try each search strategy in order
            search_paths = []

            # Strategy 1: Bundled binary
            bundled_path = cls.get_bundled_path()
            if bundled_path is not None:
                search_paths.append(bundled_path)
                if cls._validate_binary(bundled_path):
                    logger.info(f"Found bundled libak binary at: {bundled_path}")
                    cls._cached_path = bundled_path
                    return bundled_path

            # Strategy 2: System library paths
            system_paths = cls.get_system_paths()
            search_paths.extend(system_paths)
            for path in system_paths:
                if cls._validate_binary(path):
                    logger.info(f"Found system libak binary at: {path}")
                    cls._cached_path = path
                    return path

            # Strategy 3: Environment variable
            env_path = os.environ.get("LIBAK_PATH")
            if env_path:
                search_paths.append(env_path)
                if cls._validate_binary(env_path):
                    logger.info(f"Found libak binary via LIBAK_PATH at: {env_path}")
                    cls._cached_path = env_path
                    return env_path

            # Strategy 4: Current directory
            cwd_path = cls._get_cwd_path()
            search_paths.append(cwd_path)
            if cls._validate_binary(cwd_path):
                logger.info(f"Found libak binary in current directory: {cwd_path}")
                cls._cached_path = cwd_path
                return cwd_path

            # No binary found
            logger.error(f"libak binary not found. Searched paths: {search_paths}")
            raise LibakNotFoundError(
                "libak binary not found in any of the search locations",
                search_paths=search_paths,
                platform=get_platform_tag(),
            )

    @classmethod
    def get_bundled_path(cls) -> Optional[str]:
        """
        Get the path to a bundled libak binary if available.

        Searches for the libak binary in:
        1. {package_dir}/_binaries/{platform}/libak.{so|dylib}  (new unified structure)
        2. {package_dir}/_libak/libak.{so|dylib}  (legacy structure for backward compatibility)

        Returns:
            Path to the bundled binary, or None if it doesn't exist

        Raises:
            LibakNotFoundError: If the current platform is not supported
        """
        try:
            platform_tag = get_platform_tag()
            filename = get_libak_filename()
            package_dir = Path(__file__).parent

            # Strategy 1: New unified _binaries directory structure
            new_bundled_path = package_dir / "_binaries" / platform_tag / filename
            if new_bundled_path.exists():
                return str(new_bundled_path.absolute())

            # Strategy 2: Legacy _libak directory for backward compatibility
            legacy_bundled_path = package_dir / "_libak" / filename
            if legacy_bundled_path.exists():
                return str(legacy_bundled_path.absolute())

            logger.debug(
                f"No bundled libak binary found at: {new_bundled_path} or {legacy_bundled_path} "
                f"(expected for bundled installations)"
            )
            return None
        except LibakNotFoundError:
            # Platform detection failed, re-raise
            raise
        except Exception as e:
            logger.debug(f"Error checking bundled path: {e}")
            return None

    @classmethod
    def get_system_paths(cls) -> List[str]:
        """
        Get standard system library paths for the current platform.

        Returns a list of standard system locations where libak might be
        installed. The paths are platform-specific:

        macOS:
            - /usr/local/lib
            - /opt/local/lib (MacPorts)
            - /usr/local/opt/libak/lib (Homebrew)

        Linux:
            - /usr/local/lib
            - /usr/lib
            - /usr/lib/x86_64-linux-gnu (Debian/Ubuntu)

        Returns:
            List of system library paths to search

        Raises:
            LibakNotFoundError: If the current platform is not supported
        """
        try:
            platform_tag = get_platform_tag()
            filename = get_libak_filename()
            system = sys.platform.lower()

            paths = []

            if system == "darwin":
                # macOS paths
                paths.extend([
                    f"/usr/local/lib/{filename}",
                    f"/opt/local/lib/{filename}",
                    f"/usr/local/opt/libak/lib/{filename}",
                ])
            elif system == "linux":
                # Linux paths
                machine = platform_machine()
                paths.extend([
                    f"/usr/local/lib/{filename}",
                    f"/usr/lib/{filename}",
                ])
                # Add architecture-specific paths
                if machine in ("x86_64", "AMD64"):
                    paths.append(f"/usr/lib/x86_64-linux-gnu/{filename}")
                elif machine in ("arm64", "aarch64"):
                    paths.append(f"/usr/lib/aarch64-linux-gnu/{filename}")

            return paths
        except LibakNotFoundError:
            # Platform detection failed, re-raise
            raise
        except Exception as e:
            logger.debug(f"Error getting system paths: {e}")
            return []

    @staticmethod
    def _get_cwd_path() -> str:
        """
        Get the expected path to libak in the current working directory.

        Returns:
            Expected path to libak in the current directory
        """
        filename = get_libak_filename()
        return os.path.join(os.getcwd(), filename)

    @staticmethod
    def _validate_binary(path: str) -> bool:
        """
        Validate that a binary exists and is readable.

        Checks if the specified path:
        1. Exists
        2. Is a file (not a directory)
        3. Is readable

        Args:
            path: Path to the binary to validate

        Returns:
            True if the binary exists and is readable, False otherwise
        """
        try:
            path_obj = Path(path)

            # Check if file exists
            if not path_obj.exists():
                logger.debug(f"Binary does not exist: {path}")
                return False

            # Check if it's a file
            if not path_obj.is_file():
                logger.debug(f"Path is not a file: {path}")
                return False

            # Check if it's readable
            if not os.access(path, os.R_OK):
                logger.debug(f"Binary is not readable: {path}")
                return False

            logger.debug(f"Binary validation succeeded: {path}")
            return True
        except Exception as e:
            logger.debug(f"Error validating binary at {path}: {e}")
            return False

    @classmethod
    def reset_cache(cls) -> None:
        """
        Reset the cached binary path.

        This method is primarily useful for testing. It clears the cached
        binary path, forcing the next call to find() to perform a fresh search.
        """
        with cls._cache_lock:
            cls._cached_path = None
            logger.debug("Binary path cache cleared")


# Module-level convenience functions

def find_libak() -> str:
    """
    Convenience function to find the libak binary.

    This is a module-level wrapper around LibakBinaryLocator.find() for
    simple use cases where only the path is needed.

    Returns:
        Absolute path to the libak binary

    Raises:
        LibakNotFoundError: If the binary cannot be found
    """
    return LibakBinaryLocator.find()


def get_libak_platform() -> str:
    """
    Convenience function to get the platform tag.

    This is a module-level wrapper around get_platform_tag() for cases where
    only the platform identifier is needed.

    Returns:
        Platform identifier string

    Raises:
        LibakNotFoundError: If the platform is not supported
    """
    return get_platform_tag()


def find_kernel_image() -> Optional[str]:
    """
    Convenience function to find the bundled kernel image.

    Searches for the kernel image in the package:
    1. {package_dir}/_binaries/{platform}/kernel.img (new unified structure)
    2. {package_dir}/_kernel/{platform}/kernel.img (legacy structure)

    Returns:
        Absolute path to the kernel image, or None if not found

    Raises:
        LibakNotFoundError: If the platform is not supported
    """
    try:
        platform_tag = get_platform_tag()
        package_dir = Path(__file__).parent

        # Strategy 1: New unified _binaries directory structure
        new_path = package_dir / "_binaries" / platform_tag / "kernel.img"
        if new_path.exists():
            return str(new_path.absolute())

        # Strategy 2: Legacy _kernel directory for backward compatibility
        legacy_path = package_dir / "_kernel" / platform_tag / "kernel.img"
        if legacy_path.exists():
            return str(legacy_path.absolute())

        logger.debug(
            f"Kernel image not found at: {new_path} or {legacy_path} "
            f"(not required for all use cases)"
        )
        return None
    except LibakNotFoundError:
        # Platform detection failed, re-raise
        raise
    except Exception as e:
        logger.debug(f"Error finding kernel image: {e}")
        return None
