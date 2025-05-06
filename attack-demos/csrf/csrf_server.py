# The malicious file promotion.html hosting the CSRF attack must be
# served from a local server. If served directly from the file
# (using "file:///Users/..."), the browser will block the POST request.
# Code below provided by Claude 3.7 Sonnet.
# Chat: https://claude.ai/share/121e97a8-60e6-4a5b-b292-aa612144e379
import subprocess
import sys


def start_http_server(port=8080):
    """Start a simple HTTP server using Python's built-in module as a subprocess"""
    print(f"Starting server at http://localhost:{port}/")
    try:
        # This runs the Python module as a separate process
        subprocess.run([sys.executable, "-m", "http.server", str(port)])
    except KeyboardInterrupt:
        print("\nServer stopped.")


if __name__ == "__main__":
    start_http_server()
