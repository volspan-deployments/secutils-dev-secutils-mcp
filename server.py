from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
import uvicorn
import threading
from fastmcp import FastMCP
import httpx
import os
from typing import Optional
import time
import hmac
import hashlib
import base64
import json

mcp = FastMCP("secutils-dev")


def _parse_duration_to_seconds(duration_str: str) -> int:
    """Parse a human-readable duration string to seconds."""
    duration_str = duration_str.strip().lower()
    multipliers = {
        "year": 365 * 24 * 3600,
        "years": 365 * 24 * 3600,
        "month": 30 * 24 * 3600,
        "months": 30 * 24 * 3600,
        "week": 7 * 24 * 3600,
        "weeks": 7 * 24 * 3600,
        "day": 24 * 3600,
        "days": 24 * 3600,
        "hour": 3600,
        "hours": 3600,
        "minute": 60,
        "minutes": 60,
        "min": 60,
        "second": 1,
        "seconds": 1,
        "sec": 1,
    }
    for unit, secs in multipliers.items():
        if duration_str.endswith(unit):
            num_part = duration_str[: -len(unit)].strip()
            try:
                return int(num_part) * secs
            except ValueError:
                pass
    # Try parsing as plain integer seconds
    try:
        return int(duration_str)
    except ValueError:
        raise ValueError(f"Cannot parse duration: {duration_str}")


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _generate_jwt(secret: str, sub: str, exp_seconds: int) -> str:
    """Generate a HS256 JWT token."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": sub,
        "exp": int(time.time()) + exp_seconds,
    }
    header_encoded = _base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_encoded = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_encoded}.{payload_encoded}"
    signature = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    signature_encoded = _base64url_encode(signature)
    return f"{signing_input}.{signature_encoded}"


@mcp.tool()
async def get_server_status(
    base_url: Optional[str] = "http://localhost:7070",
) -> dict:
    """
    Check the current status of the Secutils.dev server, including health, version,
    and availability. Use this to verify the server is running before performing
    other operations or to diagnose connectivity issues.
    """
    base_url = (base_url or "http://localhost:7070").rstrip("/")
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(f"{base_url}/api/status")
            return {
                "status_code": response.status_code,
                "ok": response.status_code == 200,
                "body": response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text,
            }
        except httpx.ConnectError as e:
            return {"ok": False, "error": f"Connection failed: {str(e)}"}
        except httpx.TimeoutException as e:
            return {"ok": False, "error": f"Request timed out: {str(e)}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}


@mcp.tool()
async def signin_user(
    email: str,
    password: str,
    base_url: Optional[str] = "http://localhost:7070",
) -> dict:
    """
    Authenticate a user with their credentials and obtain a session or token.
    Use this before making authenticated API calls that require a logged-in user context.
    """
    base_url = (base_url or "http://localhost:7070").rstrip("/")
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            response = await client.post(
                f"{base_url}/api/signin",
                json={"email": email, "password": password},
                headers={"Content-Type": "application/json"},
            )
            result = {
                "status_code": response.status_code,
                "ok": response.status_code in (200, 201),
            }
            try:
                result["body"] = response.json()
            except Exception:
                result["body"] = response.text
            return result
        except httpx.ConnectError as e:
            return {"ok": False, "error": f"Connection failed: {str(e)}"}
        except httpx.TimeoutException as e:
            return {"ok": False, "error": f"Request timed out: {str(e)}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}


@mcp.tool()
async def signup_user(
    email: str,
    password: str,
    base_url: Optional[str] = "http://localhost:7070",
) -> dict:
    """
    Register a new user account on the Secutils.dev platform.
    Use this to create a new account when a user does not yet have credentials.
    """
    base_url = (base_url or "http://localhost:7070").rstrip("/")
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            response = await client.post(
                f"{base_url}/api/signup",
                json={"email": email, "password": password},
                headers={"Content-Type": "application/json"},
            )
            result = {
                "status_code": response.status_code,
                "ok": response.status_code in (200, 201),
            }
            try:
                result["body"] = response.json()
            except Exception:
                result["body"] = response.text
            return result
        except httpx.ConnectError as e:
            return {"ok": False, "error": f"Connection failed: {str(e)}"}
        except httpx.TimeoutException as e:
            return {"ok": False, "error": f"Request timed out: {str(e)}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}


@mcp.tool()
async def activate_account(
    activation_token: str,
    base_url: Optional[str] = "http://localhost:7070",
) -> dict:
    """
    Activate a newly registered user account using the activation token sent via email.
    Use this after signup to complete account verification and enable full access.
    """
    base_url = (base_url or "http://localhost:7070").rstrip("/")
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            response = await client.post(
                f"{base_url}/api/activate",
                json={"token": activation_token},
                headers={"Content-Type": "application/json"},
            )
            result = {
                "status_code": response.status_code,
                "ok": response.status_code in (200, 201),
            }
            try:
                result["body"] = response.json()
            except Exception:
                result["body"] = response.text
            return result
        except httpx.ConnectError as e:
            return {"ok": False, "error": f"Connection failed: {str(e)}"}
        except httpx.TimeoutException as e:
            return {"ok": False, "error": f"Request timed out: {str(e)}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}


@mcp.tool()
async def list_api_keys(
    auth_token: str,
    base_url: Optional[str] = "http://localhost:7070",
) -> dict:
    """
    Retrieve all API keys associated with the authenticated user's account.
    Use this to review existing API keys for programmatic access to Secutils.dev.
    """
    base_url = (base_url or "http://localhost:7070").rstrip("/")
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            response = await client.get(
                f"{base_url}/api/user/api_keys",
                headers={"Authorization": f"Bearer {auth_token}"},
            )
            result = {
                "status_code": response.status_code,
                "ok": response.status_code == 200,
            }
            try:
                result["body"] = response.json()
            except Exception:
                result["body"] = response.text
            return result
        except httpx.ConnectError as e:
            return {"ok": False, "error": f"Connection failed: {str(e)}"}
        except httpx.TimeoutException as e:
            return {"ok": False, "error": f"Request timed out: {str(e)}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}


@mcp.tool()
async def create_api_key(
    auth_token: str,
    label: str,
    base_url: Optional[str] = "http://localhost:7070",
) -> dict:
    """
    Generate a new API key for the authenticated user to allow programmatic or
    automated access to Secutils.dev features. Use this when you need a key for
    scripts, CI/CD pipelines, or integrations.
    """
    base_url = (base_url or "http://localhost:7070").rstrip("/")
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            response = await client.post(
                f"{base_url}/api/user/api_keys",
                json={"label": label},
                headers={
                    "Authorization": f"Bearer {auth_token}",
                    "Content-Type": "application/json",
                },
            )
            result = {
                "status_code": response.status_code,
                "ok": response.status_code in (200, 201),
            }
            try:
                result["body"] = response.json()
            except Exception:
                result["body"] = response.text
            return result
        except httpx.ConnectError as e:
            return {"ok": False, "error": f"Connection failed: {str(e)}"}
        except httpx.TimeoutException as e:
            return {"ok": False, "error": f"Request timed out: {str(e)}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}


@mcp.tool()
async def revoke_api_key(
    auth_token: str,
    api_key_id: str,
    base_url: Optional[str] = "http://localhost:7070",
) -> dict:
    """
    Revoke and delete an existing API key by its ID, immediately invalidating it.
    Use this to remove compromised, unused, or outdated keys to maintain security hygiene.
    """
    base_url = (base_url or "http://localhost:7070").rstrip("/")
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            response = await client.delete(
                f"{base_url}/api/user/api_keys/{api_key_id}",
                headers={"Authorization": f"Bearer {auth_token}"},
            )
            result = {
                "status_code": response.status_code,
                "ok": response.status_code in (200, 204),
            }
            try:
                result["body"] = response.json()
            except Exception:
                result["body"] = response.text
            return result
        except httpx.ConnectError as e:
            return {"ok": False, "error": f"Connection failed: {str(e)}"}
        except httpx.TimeoutException as e:
            return {"ok": False, "error": f"Request timed out: {str(e)}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}


@mcp.tool()
async def generate_jwt_token(
    secret: str,
    sub: str,
    exp: Optional[str] = "1year",
) -> dict:
    """
    Generate a signed JWT token using a secret key and configurable claims such as
    subject and expiration. Use this for creating Kratos webhook authentication tokens,
    testing JWT-protected endpoints, or any scenario requiring a signed JWT.
    The secret should match SECUTILS_SECURITY__JWT_SECRET.
    """
    try:
        exp_str = exp or "1year"
        exp_seconds = _parse_duration_to_seconds(exp_str)
        token = _generate_jwt(secret=secret, sub=sub, exp_seconds=exp_seconds)
        exp_timestamp = int(time.time()) + exp_seconds
        return {
            "ok": True,
            "token": token,
            "bearer": f"Bearer {token}",
            "sub": sub,
            "exp_seconds": exp_seconds,
            "exp_timestamp": exp_timestamp,
            "expires_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp_timestamp)),
        }
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"Failed to generate JWT: {str(e)}"}




_SERVER_SLUG = "secutils-dev-secutils"

def _track(tool_name: str, ua: str = ""):
    try:
        import urllib.request, json as _json
        data = _json.dumps({"slug": _SERVER_SLUG, "event": "tool_call", "tool": tool_name, "user_agent": ua}).encode()
        req = urllib.request.Request("https://www.volspan.dev/api/analytics/event", data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=1)
    except Exception:
        pass

async def health(request):
    return JSONResponse({"status": "ok", "server": mcp.name})

async def tools(request):
    registered = await mcp.list_tools()
    tool_list = [{"name": t.name, "description": t.description or ""} for t in registered]
    return JSONResponse({"tools": tool_list, "count": len(tool_list)})

sse_app = mcp.http_app(transport="sse")

app = Starlette(
    routes=[
        Route("/health", health),
        Route("/tools", tools),
        Mount("/", sse_app),
    ],
    lifespan=sse_app.lifespan,
)
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
