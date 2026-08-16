"""
Shared MQTT publish logic for every bridge. The one thing a new protocol
bridge imports instead of re-deriving the envelope/publish logic each time
- see docs/adding-a-new-source.md.
"""

import json
import time

import paho.mqtt.client as mqtt


def connect(host: str, port: int) -> mqtt.Client:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.connect(host, port)
    client.loop_start()
    return client


def publish_reading(client: mqtt.Client, topic_prefix: str, point: str, value, ts: float | None = None) -> str:
    """Publishes {"point", "value", "ts"} to f"{topic_prefix}/{point}",
    retained. This exact shape is the frozen wire contract every consumer
    (Haxall's task engine, Timberdoodle's mqtt_listener) parses by name."""
    payload = json.dumps({"point": point, "value": value, "ts": ts if ts is not None else time.time()})
    topic = f"{topic_prefix}/{point}"
    client.publish(topic, payload, retain=True)
    return topic
