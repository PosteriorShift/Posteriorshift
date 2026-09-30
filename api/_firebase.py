import json
import os
import firebase_admin
from firebase_admin import credentials, messaging

_app = None

def get_app():
    global _app
    if _app is not None:
        return _app

    raw = os.environ["FIREBASE_SERVICE_ACCOUNT"]
    info = json.loads(raw)
    if "private_key" in info:
        info["private_key"] = info["private_key"].replace("\\n", "\n")

    cred = credentials.Certificate(info)
    _app = firebase_admin.initialize_app(cred)
    return _app

def send_push(token, title, body, priority="high"):
    get_app()
    message = messaging.Message(
        token=token,
        notification=messaging.Notification(title=title, body=body),
        data={"title": title, "body": body, "priority": priority},
        android=messaging.AndroidConfig(
            priority="high" if priority == "high" else "normal",
            notification=messaging.AndroidNotification(channel_id="vv_default"),
        ),
    )
    return messaging.send(message)
