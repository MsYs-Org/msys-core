import json
import socket
from typing import Any

MAX_PACKET = 256 * 1024


class ProtocolError(RuntimeError):
    pass


def encode(message: dict[str, Any]) -> bytes:
    data = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_PACKET:
        raise ProtocolError("mIPC packet is too large")
    return data


def decode(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_PACKET:
        raise ProtocolError("mIPC packet is too large")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"invalid mIPC packet: {exc}") from exc
    if not isinstance(value, dict):
        raise ProtocolError("mIPC packet must be an object")
    msg_type = value.get("type")
    if not isinstance(msg_type, str):
        raise ProtocolError("mIPC packet requires string type")
    return value


def send_packet(sock: socket.socket, message: dict[str, Any]) -> None:
    sock.sendall(encode(message))


def recv_packet(sock: socket.socket) -> dict[str, Any] | None:
    try:
        data = sock.recv(MAX_PACKET + 1)
    except BlockingIOError:
        return None
    if not data:
        return {"type": "eof"}
    return decode(data)
