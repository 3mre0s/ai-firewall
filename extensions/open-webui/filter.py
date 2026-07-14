"""
title: AI Firewall Guard
author: Local AI Firewall
author_url: https://github.com/3mre0s/ai-firewall
version: 0.1.0
required_open_webui_version: 0.3.9
description: Thin adapter that forwards chat content to the Go-based AI Firewall
             (/v1/check) and blocks disallowed prompts/responses.
"""

# ---------------------------------------------------------------------------
# What this file is
# ---------------------------------------------------------------------------
# This is a *thin* Open WebUI "Filter Function". It contains no detection
# logic of its own. Instead it delegates every decision to an external Go
# service (the "AI Firewall") over HTTP:
#
#     Open WebUI  --(POST /v1/check)-->  Go AI Firewall  --> {allowed, reason}
#
# Open WebUI calls two hooks around every chat completion:
#   * inlet(...)  runs BEFORE the request reaches the model  (guards the prompt)
#   * outlet(...) runs AFTER the model produced a response   (guards the reply)
#
# If the firewall says a message is not allowed, we raise an Exception, which
# Open WebUI surfaces to the user as an error and aborts the request.
# ---------------------------------------------------------------------------

from typing import Optional

import requests
from pydantic import BaseModel, Field


class Filter:
    # -----------------------------------------------------------------------
    # Valves — admin-configurable settings
    # -----------------------------------------------------------------------
    # A "Valve" is a Pydantic field that Open WebUI renders as an editable
    # setting in the Admin Panel (Admin Panel > Functions > AI Firewall Guard
    # > the gear/valve icon). Changing a valve does NOT require editing code.
    class Valves(BaseModel):
        GO_FIREWALL_URL: str = Field(
            default="http://localhost:8080",
            description="Base URL of the Go AI Firewall service (no trailing slash).",
        )
        TIMEOUT_SECONDS: float = Field(
            default=5.0,
            description="How long to wait for the firewall to answer, in seconds.",
        )
        FAIL_OPEN: bool = Field(
            default=False,
            description=(
                "Behaviour when the firewall is unreachable. "
                "False = fail CLOSED (block the request, safer default). "
                "True  = fail OPEN (allow the request through)."
            ),
        )
        # 'priority' controls the order in which filters run. Lower numbers run
        # first. We keep it at 0 so this guard runs before any other filter and
        # can reject bad input before other filters waste work on it.
        priority: int = Field(
            default=0,
            description="Filter execution order. Lower runs first; 0 = earliest.",
        )

    def __init__(self):
        # Instantiate the valves so Open WebUI can read/write their values.
        self.valves = self.Valves()

        # ------------------------------------------------------------------
        # is_global
        # ------------------------------------------------------------------
        # There is no `is_global` attribute to set in code. A filter is made
        # global by an admin toggle in the UI:
        #   Admin Panel > Functions > (this function) > toggle "Global".
        # When Global is ON, Open WebUI applies this filter to EVERY model
        # automatically. When OFF, it only runs for models it is explicitly
        # attached to. Enabling Global is the recommended way to enforce the
        # firewall across the whole instance.

        # ------------------------------------------------------------------
        # file_handler
        # ------------------------------------------------------------------
        # Setting `self.file_handler = True` would tell Open WebUI that this
        # filter takes over file-upload handling (e.g. RAG pre-processing).
        # We do NOT handle files here, so we leave it unset (default False) and
        # let Open WebUI perform its normal file handling.
        # self.file_handler = True

    # -----------------------------------------------------------------------
    # Internal helper: call the Go firewall's /v1/check endpoint.
    # -----------------------------------------------------------------------
    def _call(self, content: str, user: str, direction: str) -> Optional[dict]:
        """POST the content to the Go engine and return the parsed verdict.

        `direction` is "inlet" (mask user → model) or "outlet" (restore /
        leak-check model → user); it is forwarded to the engine so it runs the
        correct path.

        Returns the response dict when the content is allowed. Raises an
        Exception when the engine blocks it, or when the engine is unreachable
        and FAIL_OPEN is False. Returns None when the engine is unreachable but
        FAIL_OPEN is True (fail open — allow, no substitution possible).
        """
        # Nothing to check — allow, nothing to substitute.
        if not content:
            return None

        url = self.valves.GO_FIREWALL_URL.rstrip("/") + "/v1/check"
        payload = {"content": content, "user": user, "direction": direction}

        try:
            resp = requests.post(
                url,
                json=payload,
                timeout=self.valves.TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.RequestException as exc:
            # Covers timeouts, connection errors, DNS failures, non-2xx, etc.
            if self.valves.FAIL_OPEN:
                # Fail OPEN: log and let the request through unmodified.
                print(f"[AI Firewall] {direction}: firewall unreachable, failing OPEN: {exc}")
                return None
            # Fail CLOSED: block the request.
            raise Exception(
                "AI Firewall is unreachable and FAIL_OPEN is disabled, "
                "so the request was blocked for safety."
            ) from exc
        except ValueError as exc:
            # Response was not valid JSON. Treat like an unreachable service.
            if self.valves.FAIL_OPEN:
                print(f"[AI Firewall] {direction}: invalid response, failing OPEN: {exc}")
                return None
            raise Exception(
                "AI Firewall returned an invalid response and FAIL_OPEN is "
                "disabled, so the request was blocked for safety."
            ) from exc

        # Engine contract: {"allowed": bool, "reason": "<snake_case>", ...}.
        # `reason` is a machine-readable code (e.g. "masking_failed_vault_full",
        # "secret_leak_in_output"); surface it verbatim so it can be logged.
        if not data.get("allowed", False):
            reason = data.get("reason") or "content_blocked"
            raise Exception(f"Blocked by AI Firewall: {reason}")

        return data

    # -----------------------------------------------------------------------
    # Helpers: read / replace the last message with a given role.
    # -----------------------------------------------------------------------
    @staticmethod
    def _last_message(body: dict, role: str) -> str:
        messages = body.get("messages", []) or []
        for message in reversed(messages):
            if message.get("role") == role:
                content = message.get("content", "")
                # Content can be a plain string or a list of multimodal parts.
                if isinstance(content, list):
                    return " ".join(
                        part.get("text", "")
                        for part in content
                        if isinstance(part, dict) and part.get("type") == "text"
                    )
                return content or ""
        return ""

    @staticmethod
    def _set_last_message(body: dict, role: str, new_content: str) -> None:
        """Replace the text of the last message with `role`.

        Only plain-string message contents are substituted. Multimodal (list)
        contents are left untouched to avoid dropping non-text parts (images,
        etc.) — the block decision still applies to them, but masked/restored
        text substitution is skipped. This keeps the adapter thin and lossless.
        """
        messages = body.get("messages", []) or []
        for message in reversed(messages):
            if message.get("role") == role:
                if isinstance(message.get("content"), str):
                    message["content"] = new_content
                return

    @staticmethod
    def _user_id(__user__: Optional[dict]) -> str:
        if not __user__:
            return "anonymous"
        return __user__.get("id") or __user__.get("email") or __user__.get("name") or "anonymous"

    # -----------------------------------------------------------------------
    # inlet — guard + mask the incoming prompt (runs BEFORE the model)
    # -----------------------------------------------------------------------
    def inlet(self, body: dict, __user__: Optional[dict] = None) -> dict:
        # Extract the latest user message from the request body.
        content = self._last_message(body, role="user")
        user = self._user_id(__user__)

        # Ask the engine to mask it. Raises if the prompt is not allowed
        # (e.g. the vault was full and a secret could not be masked).
        data = self._call(content, user=user, direction="inlet")

        # Substitute the masked text so the model never sees the raw secrets.
        # The engine only returns masked_content when it actually changed.
        if data:
            masked = data.get("masked_content")
            if masked:
                self._set_last_message(body, role="user", new_content=masked)

        return body

    # -----------------------------------------------------------------------
    # outlet — restore + leak-check the model's response (runs AFTER the model)
    # -----------------------------------------------------------------------
    def outlet(self, body: dict, __user__: Optional[dict] = None) -> dict:
        # NOTE: outlet is invoked reliably for chats made through the Open WebUI
        # frontend, but it may NOT fire for direct/raw calls to the OpenAI-
        # compatible API (/api/chat/completions) or for some streaming paths.
        # Do not rely on outlet as your only line of defence — inlet is the
        # dependable guard. Treat outlet as best-effort response filtering.
        #
        # On this path the engine (a) blocks if the reply contains a raw,
        # unmasked secret, and (b) restores any vault labels the model echoed
        # back into their original values, so the user sees real data.
        content = self._last_message(body, role="assistant")
        user = self._user_id(__user__)

        data = self._call(content, user=user, direction="outlet")

        # Substitute the restored text so the user sees originals, not labels.
        if data:
            restored = data.get("restored_content")
            if restored:
                self._set_last_message(body, role="assistant", new_content=restored)

        return body
