"""TEST LAB ONLY: a tiny OpenAI-compatible chat server with deterministic tool use.

Turn 1 (no tool result yet after the last user message): call a tool chosen from the question.
Turn 2: answer by summarising the JSON the tool returned. Lets the whole chat pipeline be
tested end to end without an API key. Never use as a real model.
"""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def pick_tool(question: str, tools: set[str]) -> tuple[str, dict]:
    q = question.lower()
    if "cek ulang" in q or "assess" in q:
        return "propose_action", {"action": "run_assessment", "reason": "User meminta pengecekan ulang."}
    if "red" in q or "status" in q:
        return "list_assets", {"status": "RED"}
    if "temuan" in q or "finding" in q or "malware" in q:
        return "list_findings", {"all_assets": True, "min_severity": "HIGH"}
    return "dashboard_summary", {}


def answer(tool: str, data: dict) -> str:
    if tool == "list_assets":
        names = ", ".join(a["name"] for a in data.get("assets", [])) or "tidak ada"
        return f"**Fakta**: {data.get('count', 0)} asset berstatus RED: {names}.\n\n**Rekomendasi**: buka temuan tiap asset."
    if tool == "list_findings":
        lines = [f"- [{f['severity']}] {f['asset']}: {f['title']}" for f in data.get("findings", [])[:10]]
        return "**Fakta** — temuan HIGH/CRITICAL aktif:\n" + ("\n".join(lines) or "- tidak ada")
    if tool == "propose_action":
        return "Saya sudah menyiapkan usulan assessment. Tekan tombol konfirmasi bila setuju."
    return "**Ringkasan**: " + json.dumps(data, ensure_ascii=False)[:600]


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        msgs = body["messages"]
        last_user = max(i for i, m in enumerate(msgs) if m["role"] == "user")
        after = msgs[last_user + 1:]
        tools = {t["function"]["name"] for t in body.get("tools", [])}
        tool_msgs = [m for m in after if m["role"] == "tool"]
        if tools and not tool_msgs:
            name, args = pick_tool(msgs[last_user]["content"], tools)
            message = {"role": "assistant", "content": None, "tool_calls": [
                {"id": f"call_{int(time.time() * 1000)}", "type": "function",
                 "function": {"name": name, "arguments": json.dumps(args)}}]}
            finish = "tool_calls"
        else:
            if tool_msgs:
                call = next(m for m in after if m.get("tool_calls"))["tool_calls"][0]["function"]["name"]
                raw = tool_msgs[-1]["content"]
                data = json.loads(raw[raw.index("{"):]) if "{" in raw else {}
                text = answer(call, data)
            else:
                text = "OK"
            message, finish = {"role": "assistant", "content": text}, "stop"
        out = json.dumps({"id": "chatcmpl-lab", "object": "chat.completion", "created": int(time.time()),
                          "model": body["model"], "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                          "usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
