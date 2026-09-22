import asyncio
import types

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer

from blfinder.core.auth.preflight import run_auth_preflight, _has_any_credentials


def make_config(**overrides):
    base = dict(
        target_url="", auth_token="", api_key_sid="", api_key_secret="",
        cookies={}, headers={}, refresh_config=None, verify_ssl=False,
        timeout=5, proxy="",
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


def run(coro):
    return asyncio.run(coro)


def test_no_credentials_means_check_is_skipped():
    config = make_config(target_url="https://example.com")
    result = run(run_auth_preflight(config))
    assert result.performed is False


async def _serve(handler):
    app = web.Application()
    app.router.add_get("/", handler)
    server = TestServer(app)
    await server.start_server()
    return server


def test_valid_token_passes_check():
    async def handler(request):
        if request.headers.get("Authorization") == "Bearer good-token":
            return web.Response(text='{"user": "jane"}', status=200)
        return web.Response(text='{"error": "unauthorized"}', status=401)

    async def scenario():
        server = await _serve(handler)
        try:
            config = make_config(
                target_url=f"http://127.0.0.1:{server.port}/",
                auth_token="good-token",
            )
            return await run_auth_preflight(config)
        finally:
            await server.close()

    result = run(scenario())
    assert result.performed is True
    assert result.passed is True
    assert result.authed_status == 200


def test_invalid_token_fails_check():
    async def handler(request):
        if request.headers.get("Authorization") == "Bearer good-token":
            return web.Response(text='{"user": "jane"}', status=200)
        return web.Response(text='{"error": "unauthorized"}', status=401)

    async def scenario():
        server = await _serve(handler)
        try:
            config = make_config(
                target_url=f"http://127.0.0.1:{server.port}/",
                auth_token="wrong-token",
            )
            return await run_auth_preflight(config)
        finally:
            await server.close()

    result = run(scenario())
    assert result.performed is True
    assert result.passed is False
    assert result.authed_status == 401


def test_identical_response_regardless_of_auth_is_inconclusive():
    async def handler(request):
        return web.Response(text='{"public": true}', status=200)

    async def scenario():
        server = await _serve(handler)
        try:
            config = make_config(
                target_url=f"http://127.0.0.1:{server.port}/",
                auth_token="some-token",
            )
            return await run_auth_preflight(config)
        finally:
            await server.close()

    result = run(scenario())
    assert result.performed is True
    assert result.passed is True
    assert result.inconclusive is True
