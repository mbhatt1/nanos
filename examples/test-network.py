#!/usr/bin/env python3
"""
Authority Kernel - Network Connectivity Test

Simple test to verify HTTPS works through the Authority Kernel.
No API key required - just tests network connectivity.

Usage:
  minops run examples/test-network.py --allow-llm
"""

import os
import sys
import socket
import ssl


def test_dns_resolution():
    """Test DNS resolution works."""
    print("Testing DNS resolution...")

    hosts = [
        "api.openai.com",
        "api.anthropic.com",
        "www.google.com",
    ]

    for host in hosts:
        try:
            ip = socket.gethostbyname(host)
            print(f"  [OK] {host} -> {ip}")
        except socket.gaierror as e:
            print(f"  [FAIL] {host}: {e}")
            return False

    print()
    return True


def test_tcp_connect():
    """Test TCP connection to HTTPS port."""
    print("Testing TCP connectivity...")

    endpoints = [
        ("api.openai.com", 443),
        ("api.anthropic.com", 443),
    ]

    for host, port in endpoints:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            sock.close()
            print(f"  [OK] {host}:{port} - TCP connected")
        except socket.error as e:
            print(f"  [FAIL] {host}:{port}: {e}")
            return False

    print()
    return True


def test_tls_handshake():
    """Test TLS handshake works."""
    print("Testing TLS handshake...")

    endpoints = [
        ("api.openai.com", 443),
    ]

    # Get SSL cert path from environment
    cert_file = os.environ.get("SSL_CERT_FILE", "/etc/ssl/cert.pem")
    cert_dir = os.environ.get("SSL_CERT_DIR", "/etc/ssl/certs")

    print(f"  Using cert file: {cert_file}")
    print(f"  Using cert dir: {cert_dir}")

    for host, port in endpoints:
        try:
            context = ssl.create_default_context()

            # Try to load CA certs
            if os.path.exists(cert_file):
                context.load_verify_locations(cafile=cert_file)
            elif os.path.exists(cert_dir):
                context.load_verify_locations(capath=cert_dir)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            wrapped = context.wrap_socket(sock, server_hostname=host)
            wrapped.connect((host, port))

            cert = wrapped.getpeercert()
            wrapped.close()

            print(f"  [OK] {host}:{port} - TLS handshake successful")
            if cert:
                subject = dict(x[0] for x in cert.get('subject', []))
                print(f"       Certificate CN: {subject.get('commonName', 'N/A')}")
        except ssl.SSLError as e:
            print(f"  [FAIL] {host}:{port} SSL error: {e}")
            return False
        except socket.error as e:
            print(f"  [FAIL] {host}:{port} socket error: {e}")
            return False

    print()
    return True


def test_http_request():
    """Test actual HTTP request."""
    print("Testing HTTP request...")

    try:
        import urllib.request
        import urllib.error

        # Test with a simple HEAD request to avoid large response
        url = "https://api.openai.com/v1/models"

        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", "Bearer test-key")

        try:
            response = urllib.request.urlopen(req, timeout=10)
            print(f"  [OK] {url} - Status: {response.status}")
        except urllib.error.HTTPError as e:
            # 401 is expected (invalid key), but means we reached the server
            if e.code == 401:
                print(f"  [OK] {url} - Reached server (401 expected with test key)")
            else:
                print(f"  [WARN] {url} - HTTP {e.code}: {e.reason}")

        return True

    except Exception as e:
        print(f"  [FAIL] HTTP request failed: {e}")
        return False


def main():
    print("=" * 60)
    print("Authority Kernel - Network Connectivity Test")
    print("=" * 60)
    print()

    print("Environment:")
    print(f"  Python: {sys.version.split()[0]}")
    print(f"  SSL_CERT_FILE: {os.environ.get('SSL_CERT_FILE', '(not set)')}")
    print(f"  SSL_CERT_DIR: {os.environ.get('SSL_CERT_DIR', '(not set)')}")
    print()

    results = []

    results.append(("DNS Resolution", test_dns_resolution()))
    results.append(("TCP Connect", test_tcp_connect()))
    results.append(("TLS Handshake", test_tls_handshake()))
    results.append(("HTTP Request", test_http_request()))

    print("=" * 60)
    print("Summary:")
    print("=" * 60)

    all_passed = True
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"  {name}: {status}")
        if not passed:
            all_passed = False

    print()
    if all_passed:
        print("Network connectivity test passed!")
        print("HTTPS connections work through Authority Kernel.")
    else:
        print("Some tests failed.")
        print("Make sure you're running with: --allow-llm")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
