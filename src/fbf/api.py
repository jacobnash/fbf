"""
FBF's discover -> learn -> create-connection API - the "SkySpark-easy, via
API" surface. Stdlib http.server, same reasoning as
timberdoodle/ingest_api.py: 5 routes doesn't clear the bar for a new web
framework dependency. Grew from BACnet-only to also cover Modbus discovery/
connections and a device registry (periodic scan results + credentials) -
same handler, same conventions, new routes under /modbus and /devices.

Every handler - GET included, not just writes - crosses into the asyncio
loop that owns the shared bacpypes3 Application and every manager
(ConnectionManager, ModbusConnectionManager, DeviceRegistry) via
asyncio.run_coroutine_threadsafe(), rather than letting this thread touch
that state directly: that state is loop-thread-owned, full stop, one
invariant instead of several. A timeout on every .result() call is
required, not optional - an unreachable device would otherwise wedge an
HTTP thread forever with no way to answer the client.
"""

import argparse
import asyncio
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from bacpypes3.app import Application
from bacpypes3.argparse import SimpleArgumentParser

from fbf import credentials, mqtt_sink, tracing
from fbf.connection_manager import ConnectionManager
from fbf.device_registry import DeviceRegistry
from fbf.modbus_connection_manager import ModbusConnectionManager
from fbf import modbus_discovery

tracer = tracing.get_tracer(__name__)

CALL_TIMEOUT = 15.0
OPENAPI_SPEC_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "openapi.yaml")


def _run(coro, loop: asyncio.AbstractEventLoop):
    return asyncio.run_coroutine_threadsafe(coro, loop).result(timeout=CALL_TIMEOUT)


def _redact(record: dict) -> dict:
    """Every list/get handler for a device or connection record routes
    through this - password_ciphertext never appears in an API response,
    same shape as timberdoodle/webhooks.py's `_redact_webhook`."""
    return {**record, "credential": credentials.redact(record.get("credential"))}


def make_handler(
    manager: ConnectionManager,
    modbus_manager: ModbusConnectionManager,
    device_registry: DeviceRegistry,
    loop: asyncio.AbstractEventLoop,
):
    class ConnectionsHandler(BaseHTTPRequestHandler):
        def _read_json_body(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))

        def _respond_json(self, status: int, payload) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle(self, span_name: str, fn):
            with tracer.start_as_current_span(span_name) as span:
                try:
                    fn(span)
                except TimeoutError as exc:
                    span.set_attribute("error", str(exc))
                    self._respond_json(504, {"error": "timed out waiting on the BACnet/Modbus stack"})
                except (KeyError, ValueError, json.JSONDecodeError) as exc:
                    span.set_attribute("error", str(exc))
                    self._respond_json(400, {"error": str(exc)})
                except Exception as exc:
                    span.set_attribute("error", str(exc))
                    self._respond_json(500, {"error": str(exc)})

        def _credential_body(self) -> tuple[str, dict]:
            """Shared by every .../credential PATCH handler: reads
            {username, password}, encrypts it, and returns (plaintext
            password, encrypted-record-to-store) - the caller echoes the
            plaintext once in its response, same as
            timberdoodle/webhooks.py's POST /webhooks."""
            body = self._read_json_body()
            username, password = body["username"], body["password"]
            return password, credentials.encrypt(username, password)

        def do_POST(self):
            if self.path == "/discover":
                def handle(span):
                    body = self._read_json_body()
                    devices = _run(manager.discover(**body), loop)
                    span.set_attribute("device_count", len(devices))
                    self._respond_json(200, devices)

                self._handle("api.post_discover", handle)
                return

            if self.path == "/learn":
                def handle(span):
                    body = self._read_json_body()
                    points = _run(manager.learn(body["device_address"], body["device_instance"]), loop)
                    span.set_attribute("point_count", len(points))
                    self._respond_json(200, points)

                self._handle("api.post_learn", handle)
                return

            if self.path == "/connections":
                def handle(span):
                    body = self._read_json_body()
                    credential = None
                    if body.get("credential"):
                        credential = credentials.encrypt(body["credential"]["username"], body["credential"]["password"])
                    record = _run(
                        manager.create_connection(
                            device_address=body["device_address"],
                            device_instance=body["device_instance"],
                            topic_prefix=body["topic_prefix"],
                            points=body["points"],
                            poll_interval=body.get("poll_interval", 5.0),
                            credential=credential,
                        ),
                        loop,
                    )
                    span.set_attribute("connection_id", record["id"])
                    self._respond_json(201, _redact(record))

                self._handle("api.post_connections", handle)
                return

            if self.path == "/modbus/discover":
                def handle(span):
                    body = self._read_json_body()
                    devices = _run(
                        modbus_discovery.sweep(
                            body["cidr"],
                            port=body.get("port", modbus_discovery.DEFAULT_PORT),
                            concurrency=body.get("concurrency", modbus_discovery.DEFAULT_CONCURRENCY),
                            timeout=body.get("timeout", modbus_discovery.DEFAULT_TIMEOUT),
                        ),
                        loop,
                    )
                    span.set_attribute("device_count", len(devices))
                    self._respond_json(200, devices)

                self._handle("api.post_modbus_discover", handle)
                return

            if self.path == "/modbus/connections":
                def handle(span):
                    body = self._read_json_body()
                    credential = None
                    if body.get("credential"):
                        credential = credentials.encrypt(body["credential"]["username"], body["credential"]["password"])
                    record = _run(
                        modbus_manager.create_connection(
                            host=body["host"],
                            topic_prefix=body["topic_prefix"],
                            points=body["points"],
                            port=body.get("port", 502),
                            device_id=body.get("device_id", 1),
                            poll_interval=body.get("poll_interval", 5.0),
                            credential=credential,
                        ),
                        loop,
                    )
                    span.set_attribute("connection_id", record["id"])
                    self._respond_json(201, _redact(record))

                self._handle("api.post_modbus_connections", handle)
                return

            if self.path.startswith("/devices/") and self.path.endswith("/recheck-credentials"):
                device_id = self.path[len("/devices/") : -len("/recheck-credentials")]

                def handle(span):
                    span.set_attribute("device_id", device_id)
                    record = _run(device_registry.recheck_credentials(device_id), loop)
                    if record is None:
                        self._respond_json(404, {"error": "no device with that id"})
                        return
                    self._respond_json(200, _redact(record))

                self._handle("api.post_recheck_credentials", handle)
                return

            self.send_response(404)
            self.end_headers()

        def do_PATCH(self):
            if self.path.startswith("/connections/") and self.path.endswith("/credential"):
                connection_id = self.path[len("/connections/") : -len("/credential")].rstrip("/")

                def handle(span):
                    span.set_attribute("connection_id", connection_id)
                    password, credential = self._credential_body()
                    record = _run(manager.set_credential(connection_id, credential), loop)
                    if record is None:
                        self._respond_json(404, {"error": "no connection with that id"})
                        return
                    self._respond_json(200, {"username": credential["username"], "password": password})

                self._handle("api.patch_connection_credential", handle)
                return

            if self.path.startswith("/modbus/connections/") and self.path.endswith("/credential"):
                connection_id = self.path[len("/modbus/connections/") : -len("/credential")].rstrip("/")

                def handle(span):
                    span.set_attribute("connection_id", connection_id)
                    password, credential = self._credential_body()
                    record = _run(modbus_manager.set_credential(connection_id, credential), loop)
                    if record is None:
                        self._respond_json(404, {"error": "no connection with that id"})
                        return
                    self._respond_json(200, {"username": credential["username"], "password": password})

                self._handle("api.patch_modbus_connection_credential", handle)
                return

            if self.path.startswith("/devices/") and self.path.endswith("/credential"):
                device_id = self.path[len("/devices/") : -len("/credential")].rstrip("/")

                def handle(span):
                    span.set_attribute("device_id", device_id)
                    password, credential = self._credential_body()
                    record = _run(device_registry.set_credential(device_id, credential), loop)
                    if record is None:
                        self._respond_json(404, {"error": "no device with that id"})
                        return
                    self._respond_json(200, {"username": credential["username"], "password": password})

                self._handle("api.patch_device_credential", handle)
                return

            if self.path.startswith("/devices/"):
                device_id = self.path[len("/devices/") :]

                def handle(span):
                    span.set_attribute("device_id", device_id)
                    body = self._read_json_body()
                    record = _run(device_registry.set_status(device_id, body["status"]), loop)
                    if record is None:
                        self._respond_json(404, {"error": "no device with that id"})
                        return
                    self._respond_json(200, _redact(record))

                self._handle("api.patch_device", handle)
                return

            self.send_response(404)
            self.end_headers()

        def do_GET(self):
            if self.path == "/connections":
                def handle(span):
                    connections = _run(manager.list_connections(), loop)
                    span.set_attribute("count", len(connections))
                    self._respond_json(200, [_redact(c) for c in connections])

                self._handle("api.get_connections", handle)
                return

            if self.path == "/modbus/connections":
                def handle(span):
                    connections = _run(modbus_manager.list_connections(), loop)
                    span.set_attribute("count", len(connections))
                    self._respond_json(200, [_redact(c) for c in connections])

                self._handle("api.get_modbus_connections", handle)
                return

            if self.path == "/devices":
                def handle(span):
                    devices = device_registry.list()
                    span.set_attribute("count", len(devices))
                    self._respond_json(200, [_redact(d) for d in devices])

                self._handle("api.get_devices", handle)
                return

            if self.path == "/openapi.yaml":
                with tracer.start_as_current_span("api.get_openapi_spec"):
                    with open(OPENAPI_SPEC_PATH, "rb") as f:
                        body = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/yaml")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                return

            self.send_response(404)
            self.end_headers()

        def do_DELETE(self):
            if self.path.startswith("/modbus/connections/"):
                connection_id = self.path[len("/modbus/connections/") :]

                def handle(span):
                    span.set_attribute("connection_id", connection_id)
                    deleted = _run(modbus_manager.delete_connection(connection_id), loop)
                    span.set_attribute("deleted", deleted)
                    self.send_response(204 if deleted else 404)
                    self.end_headers()

                self._handle("api.delete_modbus_connection", handle)
                return

            if self.path.startswith("/connections/"):
                connection_id = self.path[len("/connections/") :]

                def handle(span):
                    span.set_attribute("connection_id", connection_id)
                    deleted = _run(manager.delete_connection(connection_id), loop)
                    span.set_attribute("deleted", deleted)
                    self.send_response(204 if deleted else 404)
                    self.end_headers()

                self._handle("api.delete_connection", handle)
                return

            self.send_response(404)
            self.end_headers()

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

        def end_headers(self):
            # Lets a dashboard served from a different origin/port (see
            # timberdoodle/ui/devices.html) call this API directly from
            # the browser.
            self.send_header("Access-Control-Allow-Origin", "*")
            super().end_headers()

        def log_message(self, fmt, *args):
            pass  # quiet by default; tracing carries the real signal

    return ConnectionsHandler


def _crash_logger(task_name: str):
    """An unhandled exception in an asyncio.Task otherwise dies silently -
    same reasoning as connection_manager.py's _make_crash_logger, applied
    to the periodic scan tasks."""

    def on_done(task: asyncio.Task) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is None:
            return
        print(f"{task_name} crashed: {exc!r}")
        with tracer.start_as_current_span("api.periodic_task_crashed") as span:
            span.set_attribute("task_name", task_name)
            span.set_attribute("error", str(exc))

    return on_done


async def async_main(args) -> None:
    app = Application.from_args(args)
    await asyncio.sleep(1)  # let transport setup finish, same as bridge.py

    mqtt_client = mqtt_sink.connect(args.mqtt_host, args.mqtt_port)
    manager = ConnectionManager(app, mqtt_client, args.state_file)
    await manager.start()

    modbus_manager = ModbusConnectionManager(mqtt_client, args.modbus_state_file)
    await modbus_manager.start()

    device_registry = DeviceRegistry(args.devices_state_file)
    await device_registry.start()

    loop = asyncio.get_event_loop()

    bacnet_scan_task = loop.create_task(
        device_registry.run_periodic_bacnet_scan(app, manager, args.bacnet_discovery_interval)
    )
    bacnet_scan_task.add_done_callback(_crash_logger("bacnet periodic scan"))

    for cidr in args.modbus_scan_cidr or []:
        modbus_scan_task = loop.create_task(
            device_registry.run_periodic_modbus_scan(cidr, modbus_manager, args.modbus_scan_interval)
        )
        modbus_scan_task.add_done_callback(_crash_logger(f"modbus periodic scan ({cidr})"))

    server = ThreadingHTTPServer(
        (args.host, args.port), make_handler(manager, modbus_manager, device_registry, loop)
    )
    server.daemon_threads = True  # unset default is False - a hung request would otherwise block shutdown

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"BACnet/Modbus discovery/connections API listening on {args.host}:{args.port}")

    try:
        await asyncio.Event().wait()
    finally:
        server.shutdown()
        # modbus_manager.close() first: an unclosed AsyncModbusTcpClient
        # leaves its own internal reconnect task alive, which stalls
        # asyncio.run()'s default task-cancellation-on-shutdown
        # indefinitely - confirmed live (see test_modbus_connection_manager.py).
        await modbus_manager.close()
        mqtt_client.loop_stop()
        app.close()


def main() -> None:
    parser = SimpleArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--mqtt-host", default="localhost")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--state-file", default="fbf-connections.json")
    parser.add_argument("--modbus-state-file", default="fbf-modbus-connections.json")
    parser.add_argument("--devices-state-file", default="fbf-devices.json")
    parser.add_argument("--bacnet-discovery-interval", type=float, default=300.0)
    parser.add_argument(
        "--modbus-scan-cidr",
        action="append",
        default=None,
        help="A subnet to periodically sweep for Modbus devices, e.g. 192.168.1.0/24. Repeatable. "
        "No default - periodic Modbus scanning only runs against subnets an operator explicitly configures.",
    )
    parser.add_argument("--modbus-scan-interval", type=float, default=600.0)
    args = parser.parse_args()

    tracing.init_tracing("fbf-api")
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
