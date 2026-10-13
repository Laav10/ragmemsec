"""Focused local-only tests for the Ollama provider and packaged registry."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ragmemsec.agent.model_provider import (
    MockModelProvider,
    OllamaModelProvider,
    OllamaProviderError,
)
from ragmemsec.attacks.scenarios import load_scenario
from ragmemsec.cli import build_provider
from ragmemsec.config import BaselineConfig, load_config
from ragmemsec.evaluation.runner import ExperimentRunner

ROOT = Path(__file__).parents[1]


@contextmanager
def fake_ollama(response_body: str, status: int = 200):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.server.request_body = self.rfile.read(
                int(self.headers["Content-Length"])
            )
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(response_body.encode("utf-8"))

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def provider_for(server) -> OllamaModelProvider:
    return OllamaModelProvider(
        "huihui_ai/qwen3-abliterated:8b-v2",
        temperature=0.0,
        max_new_tokens=128,
        base_url=f"http://127.0.0.1:{server.server_port}",
    )


def test_ollama_provider_sends_configured_model_and_extracts_usage():
    reply = json.dumps(
        {
            "choices": [
                {
                    "message": {
                        "content": '<think>reasoning</think>\n{"decision": "allowed"}'
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 11,
                "completion_tokens": 7,
                "total_tokens": 18,
            },
        }
    )
    with fake_ollama(reply) as server:
        result = provider_for(server).generate([{"role": "user", "content": "hi"}])

    sent = json.loads(server.request_body)
    assert sent["model"] == "huihui_ai/qwen3-abliterated:8b-v2"
    assert sent["temperature"] == 0
    assert sent["max_tokens"] == 128
    assert result.text.startswith("<think>reasoning</think>")
    assert result.parsing_text == '{"decision": "allowed"}'
    assert result.metadata == {
        "provider": "ollama",
        "model_id": "huihui_ai/qwen3-abliterated:8b-v2",
        "base_url": f"http://127.0.0.1:{server.server_port}",
        "finish_reason": "stop",
        "prompt_tokens": 11,
        "completion_tokens": 7,
        "total_tokens": 18,
    }


def test_ollama_provider_reports_connection_failure_without_fallback():
    provider = OllamaModelProvider(
        "requested-model",
        temperature=0.0,
        max_new_tokens=8,
        base_url="http://127.0.0.1:1",
    )
    with pytest.raises(OllamaProviderError, match="Could not connect"):
        provider.generate([])
    assert not isinstance(provider, MockModelProvider)


def test_ollama_provider_reports_http_malformed_and_missing_content_errors():
    with fake_ollama('{"error":"unavailable"}', status=503) as server:
        with pytest.raises(OllamaProviderError, match="HTTP 503"):
            provider_for(server).generate([])
    with fake_ollama("not-json") as server:
        with pytest.raises(OllamaProviderError, match="malformed JSON"):
            provider_for(server).generate([])
    with fake_ollama(json.dumps({"choices": []})) as server:
        with pytest.raises(OllamaProviderError, match="no choices"):
            provider_for(server).generate([])
    with fake_ollama(json.dumps({"choices": [{"message": {}}]})) as server:
        with pytest.raises(OllamaProviderError, match="no assistant content"):
            provider_for(server).generate([])


def test_huihui_config_builds_ollama_without_a_provider_fallback():
    config = load_config(ROOT / "configs/ollama_huihui.yaml")
    provider = build_provider(config)
    assert isinstance(provider, OllamaModelProvider)
    assert provider.model_id == "huihui_ai/qwen3-abliterated:8b-v2"
    with pytest.raises(ValueError, match="Unsupported provider"):
        build_provider(BaselineConfig(provider="not-a-provider"))


def test_ollama_real_runs_select_sentence_transformer_embeddings(monkeypatch, tmp_path):
    class FakeSentenceProvider:
        def __init__(self, model_name):
            self.model_name = model_name

        def embed(self, text):
            return [1.0]

    monkeypatch.setattr(
        "ragmemsec.evaluation.runner.SentenceTransformerEmbeddingProvider",
        FakeSentenceProvider,
    )
    config = BaselineConfig(
        model="huihui-qwen3-8b",
        provider="ollama",
        state_dir=str(tmp_path / "state"),
        artifacts_dir=str(tmp_path / "artifacts"),
    )
    provider = OllamaModelProvider(config.model_id, 0.0, 128)
    runner = ExperimentRunner(
        config,
        load_scenario(ROOT / "configs/scenarios/orion_access.yaml"),
        provider,
    )
    assert isinstance(runner.embedder, FakeSentenceProvider)
    assert runner.run_kind == "real_benchmark"


def test_packaged_model_registry_is_available_from_a_wheel(tmp_path):
    wheel_dir = tmp_path / "wheels"
    build_python = getattr(sys, "_base_executable", sys.executable)
    subprocess.run(
        [
            build_python,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
            str(ROOT),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(wheel_dir.glob("ragmemsec-*.whl"))
    venv_dir = tmp_path / "venv"
    subprocess.run([build_python, "-m", "venv", str(venv_dir)], check=True)
    wheel_python = venv_dir / "bin" / "python"
    subprocess.run(
        [str(wheel_python), "-m", "pip", "install", "--no-deps", str(wheel)],
        check=True,
        capture_output=True,
        text=True,
    )
    environment = {
        key: value for key, value in os.environ.items() if key != "PYTHONPATH"
    }
    completed = subprocess.run(
        [str(wheel_python), "-m", "ragmemsec.cli", "inspect-models"],
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout)["huihui-qwen3-8b"]["model_id"] == (
        "huihui_ai/qwen3-abliterated:8b-v2"
    )
