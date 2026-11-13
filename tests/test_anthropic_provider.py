"""
Tests for the Anthropic Messages API adapter, the wrong-provider key guard and the
masked-key scrubber. No real network calls and no real keys: httpx is mocked.
"""

import asyncio
import json
import os
import unittest
from unittest import mock

import httpx

from apis.llm_client import DEFAULT_ANTHROPIC_MODEL, LLMClient, LLMProviderError

DUMMY_ANTHROPIC_KEY = "sk-ant-test-0000000000000000000000000000000000000000-dummy"

ANTHROPIC_OK_BODY = {
    "id": "msg_test",
    "type": "message",
    "role": "assistant",
    "content": [
        {
            "type": "text",
            "text": (
                "Bonus for [ID_ABCDEF12] is [FHE_COMPUTED_BONUS].\n"
                "```json\n"
                '{"fhe_compute": {"op": "PERCENT_BONUS", "ref": "[FHE_NUM_1]", "percent": 15},'
                ' "action_intent": null}\n'
                "```"
            ),
        }
    ],
    "stop_reason": "end_turn",
}


class _Capture:
    """Records what would have been posted and returns a canned response."""

    def __init__(self, response=None, exc=None):
        self.response = response
        self.exc = exc
        self.calls = []

    def patch(self):
        capture = self

        async def fake_post(self_client, url, *args, **kwargs):
            capture.calls.append({"url": url, "headers": kwargs.get("headers"), "json": kwargs.get("json")})
            if capture.exc is not None:
                raise capture.exc
            return capture.response

        return mock.patch.object(httpx.AsyncClient, "post", new=fake_post)


class TestAnthropicProvider(unittest.TestCase):
    def test_request_shape_and_parsed_result(self):
        cap = _Capture(response=httpx.Response(200, json=ANTHROPIC_OK_BODY))
        with cap.patch():
            result = asyncio.run(
                LLMClient().generate_blind_reasoning(
                    "Evaluate bonus for [ID_ABCDEF12] on [FHE_NUM_1]", provider="anthropic", api_key=DUMMY_ANTHROPIC_KEY
                )
            )
        self.assertEqual(len(cap.calls), 1)
        call = cap.calls[0]
        self.assertEqual(call["url"], "https://api.anthropic.com/v1/messages")
        self.assertEqual(call["headers"]["x-api-key"], DUMMY_ANTHROPIC_KEY)
        self.assertEqual(call["headers"]["anthropic-version"], "2023-06-01")
        self.assertEqual(call["json"]["model"], DEFAULT_ANTHROPIC_MODEL)
        self.assertIn("max_tokens", call["json"])
        self.assertEqual(call["json"]["messages"][0]["role"], "user")
        self.assertIn("[FHE_NUM_1]", call["json"]["messages"][0]["content"])

        self.assertTrue(result["is_live_cloud"])
        self.assertEqual(result["fhe_compute"]["op"], "PERCENT_BONUS")
        # The reported request is the real one, with the credential redacted.
        wire = result["wire_request"]
        self.assertEqual(wire["url"], "https://api.anthropic.com/v1/messages")
        self.assertEqual(wire["headers_redacted"]["x-api-key"], "<redacted>")
        self.assertEqual(wire["body"], call["json"])
        self.assertNotIn(DUMMY_ANTHROPIC_KEY, json.dumps(wire))

    def test_model_override_from_environment(self):
        cap = _Capture(response=httpx.Response(200, json=ANTHROPIC_OK_BODY))
        with mock.patch.dict(os.environ, {"ANTHROPIC_MODEL": "claude-test-model"}), cap.patch():
            asyncio.run(LLMClient()._call_anthropic("blinded", DUMMY_ANTHROPIC_KEY))
        self.assertEqual(cap.calls[0]["json"]["model"], "claude-test-model")

    def test_auto_mode_routes_anthropic_prefix_to_anthropic_not_openai(self):
        cap = _Capture(response=httpx.Response(200, json=ANTHROPIC_OK_BODY))
        with cap.patch():
            asyncio.run(
                LLMClient().generate_blind_reasoning("blinded", provider="auto", api_key=DUMMY_ANTHROPIC_KEY)
            )
        self.assertEqual(cap.calls[0]["url"], "https://api.anthropic.com/v1/messages")

    def test_anthropic_key_is_never_sent_to_another_provider(self):
        for provider in ("openai", "gemini", "bedrock"):
            with self.subTest(provider=provider):
                cap = _Capture(response=httpx.Response(200, json={}))
                with cap.patch():
                    with self.assertRaises(ValueError) as cm:
                        asyncio.run(
                            LLMClient().generate_blind_reasoning(
                                "blinded", provider=provider, api_key=DUMMY_ANTHROPIC_KEY
                            )
                        )
                self.assertEqual(cap.calls, [], "the key must not leave the machine")
                self.assertNotIn(DUMMY_ANTHROPIC_KEY, str(cm.exception))
                self.assertIn("ANTHROPIC_API_KEY", str(cm.exception))

    def test_anthropic_key_in_env_slot_of_other_provider_is_refused(self):
        cap = _Capture(response=httpx.Response(200, json={}))
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": DUMMY_ANTHROPIC_KEY}), cap.patch():
            with self.assertRaises(ValueError):
                asyncio.run(LLMClient().generate_blind_reasoning("blinded", provider="openai"))
        self.assertEqual(cap.calls, [])

    def test_errors_become_provider_errors_without_the_key(self):
        cases = {
            "http 401": dict(response=httpx.Response(401, json={"error": {"message": "invalid x-api-key"}})),
            "no content": dict(response=httpx.Response(200, json={"content": [], "stop_reason": "max_tokens"})),
            "tool block only": dict(response=httpx.Response(200, json={"content": [{"type": "tool_use"}]})),
            "timeout": dict(exc=httpx.ReadTimeout("timed out")),
        }
        for name, kwargs in cases.items():
            with self.subTest(case=name):
                with _Capture(**kwargs).patch():
                    with self.assertRaises(LLMProviderError) as cm:
                        asyncio.run(LLMClient()._call_anthropic("blinded", DUMMY_ANTHROPIC_KEY))
                self.assertNotIn(DUMMY_ANTHROPIC_KEY, str(cm.exception))
                self.assertIsNotNone(cm.exception.wire_request)

    def test_env_config_reports_anthropic_without_exposing_the_key(self):
        cleared = {k: "" for k in ("GEMINI_API_KEY", "OPENAI_API_KEY", "AWS_BEARER_TOKEN_BEDROCK")}
        with mock.patch("apis.llm_client.load_dotenv_if_present"), mock.patch.dict(
            os.environ, {**cleared, "ANTHROPIC_API_KEY": DUMMY_ANTHROPIC_KEY}
        ):
            cfg = LLMClient.get_env_config()
        self.assertTrue(cfg["anthropic_configured"])
        self.assertTrue(cfg["any_live_configured"])
        self.assertEqual(cfg["recommended_default"], "anthropic")
        self.assertNotIn(DUMMY_ANTHROPIC_KEY, json.dumps(cfg))


class TestMaskedKeyScrubber(unittest.TestCase):
    def test_provider_echo_of_a_masked_key_is_removed(self):
        key = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzzzz"
        echoed = "Incorrect API key provided: sk-proj-A" + "*" * 40 + "zzzz. You can find your API key at …"
        resp = httpx.Response(401, text=json.dumps({"error": {"message": echoed}}))
        with _Capture(response=resp).patch():
            with self.assertRaises(LLMProviderError) as cm:
                asyncio.run(LLMClient()._call_openai("blinded", key))
        message = str(cm.exception)
        self.assertNotIn("sk-proj-A", message)
        self.assertNotIn("zzzz", message)
        self.assertNotIn("****", message)
        self.assertIn("<redacted>", message)


if __name__ == "__main__":
    unittest.main(verbosity=2)
