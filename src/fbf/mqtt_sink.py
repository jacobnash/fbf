"""
Shared MQTT publish logic for every bridge. The one thing a new protocol
bridge imports instead of re-deriving the envelope/publish logic each time
- see docs/adding-a-new-source.md.

Also owns the local spool: if the client isn't connected when a reading
is taken (the uplink from an on-site host to the broker is down, but this
process is still polling BACnet/Modbus locally), the reading is appended
to a JSONL file instead of dropped, and replayed on the next on_connect.
Idempotent replay relies on Timberdoodle's ingest_reading() being
idempotent on (point_uri, ts) - see timberdoodle's ingest.py.
"""

import json
import os
import threading
import time

import paho.mqtt.client as mqtt

MAX_SPOOL_ROWS = 10_000
# ponytail: fixed 10k-row ring buffer, no dynamic sizing by outage length or
# point count - bump MAX_SPOOL_ROWS or move to a real bounded queue if a
# real outage ever overflows it (this is a guess at "long enough", not
# measured).

_spool_lock = threading.Lock()


def _spool_path() -> str:
    return os.environ.get("FBF_SPOOL_FILE", "fbf-spool.jsonl")


def _read_spool(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                # A hard kill mid-append can only corrupt the last,
                # incomplete line - every prior line is already
                # newline-terminated and durable. Drop just this one.
                print(f"dropping corrupt spool line: {exc!r}")
    return records


def _write_spool(path: str, records: list[dict]) -> None:
    """Atomic write: temp file + os.replace (same pattern as
    connection_store.save) - only used for the cap-trim and post-flush
    clear, not the hot append path."""
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")
    os.replace(tmp_path, path)


def _spool_append(record: dict) -> None:
    path = _spool_path()
    with _spool_lock:
        with open(path, "a") as f:
            f.write(json.dumps(record) + "\n")
        records = _read_spool(path)
        if len(records) > MAX_SPOOL_ROWS:
            _write_spool(path, records[-MAX_SPOOL_ROWS:])


def _flush_spool(client: mqtt.Client) -> None:
    path = _spool_path()
    with _spool_lock:
        records = _read_spool(path)
        if not records:
            return
        for i, record in enumerate(records):
            if not client.is_connected():
                print(f"reconnect lost mid-flush, {len(records) - i} record(s) remain spooled")
                return
            _publish(client, record["topic_prefix"], record["point"], record["value"], record["ts"])
        os.remove(path)
        print(f"flushed {len(records)} spooled reading(s)")


def _on_connect(client, userdata, flags, reason_code, properties) -> None:
    _flush_spool(client)


def connect(host: str, port: int) -> mqtt.Client:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = _on_connect
    client.connect(host, port)
    client.loop_start()
    return client


def _publish(client: mqtt.Client, topic_prefix: str, point: str, value, ts: float) -> str:
    payload = json.dumps({"point": point, "value": value, "ts": ts})
    topic = f"{topic_prefix}/{point}"
    client.publish(topic, payload, qos=1, retain=True)
    return topic


def publish_reading(client: mqtt.Client, topic_prefix: str, point: str, value, ts: float | None = None) -> str:
    """Publishes {"point", "value", "ts"} to f"{topic_prefix}/{point}",
    retained. This exact shape is the frozen wire contract every consumer
    (Haxall's task engine, Timberdoodle's mqtt_listener) parses by name.

    If the client isn't currently connected, the reading is spooled to
    disk instead of dropped, and replayed automatically once the
    connection is back (see _on_connect)."""
    ts = ts if ts is not None else time.time()
    if not client.is_connected():
        _spool_append({"topic_prefix": topic_prefix, "point": point, "value": value, "ts": ts})
        return f"{topic_prefix}/{point}"
    return _publish(client, topic_prefix, point, value, ts)
