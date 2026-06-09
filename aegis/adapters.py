import time
import json
import httpx
from typing import Optional


class AdapterError(Exception):
    pass


class BaseAdapter:
    async def complete(self, prompt: str, system_prompt: str | None = None) -> tuple[str, float]:
        raise NotImplementedError


class OllamaAdapter(BaseAdapter):
    def __init__(self, model: str, base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")

    async def complete(self, prompt: str, system_prompt: str | None = None) -> tuple[str, float]:
        payload: dict = {"model": self.model, "prompt": prompt, "stream": False}
        if system_prompt:
            payload["system"] = system_prompt

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=180.0) as client:
                resp = await client.post(f"{self.base_url}/api/generate", json=payload)
                resp.raise_for_status()
                latency_ms = (time.monotonic() - start) * 1000
                data = resp.json()
                return data.get("response", ""), latency_ms
        except httpx.ConnectError:
            raise AdapterError(f"Cannot connect to Ollama at {self.base_url}. Is it running?")
        except httpx.HTTPStatusError as e:
            raise AdapterError(f"Ollama returned HTTP {e.response.status_code}: {e.response.text}")
        except Exception as e:
            raise AdapterError(f"Ollama request failed: {e}")


class HuggingFaceAdapter(BaseAdapter):
    def __init__(self, model: str, api_token: str):
        self.model = model
        self.api_token = api_token
        self.base_url = f"https://api-inference.huggingface.co/models/{model}"

    async def complete(self, prompt: str, system_prompt: str | None = None) -> tuple[str, float]:
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        headers = {"Authorization": f"Bearer {self.api_token}"}
        payload = {"inputs": full_prompt, "parameters": {"max_new_tokens": 512, "return_full_text": False}}

        start = time.monotonic()
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    resp = await client.post(self.base_url, json=payload, headers=headers)
                    if resp.status_code == 503:
                        wait = float(resp.headers.get("X-Wait-For", 10 * (attempt + 1)))
                        import asyncio
                        await asyncio.sleep(min(wait, 30))
                        continue
                    resp.raise_for_status()
                    latency_ms = (time.monotonic() - start) * 1000
                    data = resp.json()
                    if isinstance(data, list) and data:
                        return data[0].get("generated_text", ""), latency_ms
                    return str(data), latency_ms
            except httpx.HTTPStatusError as e:
                raise AdapterError(f"HuggingFace API HTTP {e.response.status_code}: {e.response.text}")
            except Exception as e:
                raise AdapterError(f"HuggingFace request failed: {e}")
        raise AdapterError(f"HuggingFace model {self.model} still loading after retries")


class OpenAIAdapter(BaseAdapter):
    def __init__(self, model: str, api_key: str, base_url: str = "https://api.openai.com"):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    async def complete(self, prompt: str, system_prompt: str | None = None) -> tuple[str, float]:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {"model": self.model, "messages": messages}
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

        start = time.monotonic()
        for attempt in range(4):
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    resp = await client.post(f"{self.base_url}/v1/chat/completions", json=payload, headers=headers)
                    latency_ms = (time.monotonic() - start) * 1000
                    if resp.status_code == 429:
                        import asyncio
                        wait = float(resp.headers.get("retry-after", 10 * (attempt + 1)))
                        await asyncio.sleep(min(wait, 60))
                        continue
                    if resp.status_code in (400, 422):
                        try:
                            msg = resp.json().get("error", {}).get("message", resp.text)
                        except Exception:
                            msg = resp.text
                        return f"I cannot and will not assist with that request. [API policy: {msg[:120]}]", latency_ms
                    resp.raise_for_status()
                    data = resp.json()
                    return data["choices"][0]["message"]["content"], latency_ms
            except httpx.HTTPStatusError as e:
                raise AdapterError(f"OpenAI API HTTP {e.response.status_code}: {e.response.text}")
            except Exception as e:
                raise AdapterError(f"OpenAI request failed: {e}")
        raise AdapterError("Rate limit exceeded after retries")


class AnthropicAdapter(BaseAdapter):
    def __init__(self, model: str, api_key: str):
        self.model = model
        self.api_key = api_key

    async def complete(self, prompt: str, system_prompt: str | None = None) -> tuple[str, float]:
        payload: dict = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            payload["system"] = system_prompt

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers)
                resp.raise_for_status()
                latency_ms = (time.monotonic() - start) * 1000
                data = resp.json()
                return data["content"][0]["text"], latency_ms
        except httpx.HTTPStatusError as e:
            raise AdapterError(f"Anthropic API HTTP {e.response.status_code}: {e.response.text}")
        except Exception as e:
            raise AdapterError(f"Anthropic request failed: {e}")


class OpenAICompatibleAdapter(OpenAIAdapter):
    def __init__(self, model: str, base_url: str, api_key: str = ""):
        super().__init__(model=model, api_key=api_key or "not-required", base_url=base_url)


def get_adapter(adapter_name: str, model: str, **kwargs) -> BaseAdapter:
    import os

    match adapter_name:
        case "ollama":
            return OllamaAdapter(
                model=model,
                base_url=kwargs.get("base_url") or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            )
        case "huggingface":
            token = kwargs.get("api_token") or os.getenv("HF_TOKEN", "")
            if not token:
                raise AdapterError("HuggingFace requires HF_TOKEN env var or api_token kwarg")
            return HuggingFaceAdapter(model=model, api_token=token)
        case "openai":
            key = kwargs.get("api_key") or os.getenv("OPENAI_API_KEY", "")
            if not key:
                raise AdapterError("OpenAI requires OPENAI_API_KEY env var or api_key kwarg")
            return OpenAIAdapter(model=model, api_key=key)
        case "anthropic":
            key = kwargs.get("api_key") or os.getenv("ANTHROPIC_API_KEY", "")
            if not key:
                raise AdapterError("Anthropic requires ANTHROPIC_API_KEY env var or api_key kwarg")
            return AnthropicAdapter(model=model, api_key=key)
        case "openai-compatible":
            base_url = kwargs.get("base_url") or os.getenv("OPENAI_COMPATIBLE_BASE_URL", "")
            if not base_url:
                raise AdapterError("openai-compatible requires --base-url or OPENAI_COMPATIBLE_BASE_URL")
            key = kwargs.get("api_key") or os.getenv("OPENAI_COMPATIBLE_API_KEY", "")
            return OpenAICompatibleAdapter(model=model, base_url=base_url, api_key=key)
        case _:
            raise AdapterError(f"Unknown adapter: {adapter_name}. Choose: ollama|huggingface|openai|anthropic|openai-compatible")
