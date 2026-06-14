#!/usr/bin/env python3
"""CCC SubAgent — A2A 프로토콜 기반 경량 에이전트"""
import json, signal, subprocess, os
from http.server import HTTPServer, BaseHTTPRequestHandler

# docker exec -d 의 부모 종료 / ssh disconnect 시 SIGHUP 전파 차단
signal.signal(signal.SIGHUP, signal.SIG_IGN)


class SubAgentHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            info = {
                "status": "healthy",
                "hostname": os.uname().nodename,
                "role": os.getenv("CCC_ROLE", "unknown"),
            }
            self.wfile.write(json.dumps(info).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/a2a/run_script":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            script = body.get("script", "echo ok")
            timeout = body.get("timeout", 60)
            try:
                r = subprocess.run(script, shell=True, executable="/bin/bash",
                                   capture_output=True, text=True, timeout=timeout)
                # 30000 chars — 13 도구 매트릭스 + nikto -Version 같은 verbose 출력 수용
                result = {"exit_code": r.returncode, "stdout": r.stdout[:30000], "stderr": r.stderr[:5000]}
            except subprocess.TimeoutExpired:
                result = {"exit_code": -1, "stdout": "", "stderr": "timeout"}
            except Exception as e:
                result = {"exit_code": -1, "stdout": "", "stderr": str(e)}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    port = int(os.getenv("SUBAGENT_PORT", "8002"))
    print(f"CCC SubAgent listening on :{port}", flush=True)
    HTTPServer(("0.0.0.0", port), SubAgentHandler).serve_forever()
