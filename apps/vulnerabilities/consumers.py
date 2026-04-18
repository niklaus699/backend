import json
import logging

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async

logger = logging.getLogger(__name__)


class DashboardConsumer(AsyncWebsocketConsumer):
    """
    One WebSocket connection per browser tab.
    All connections for the same organization share one channel group,
    so a single Celery broadcast reaches every connected client.

    URL pattern: ws://host/ws/dashboard/
    Auth: JWT token passed as query param ?token=<jwt>
    """

    async def connect(self):
        # Extract and validate JWT from query string
        token = self._get_token_from_scope()
        org_id = await self._validate_token(token)

        if not org_id:
            await self.close(code=4001)  # Unauthorized
            return

        self.org_id = org_id
        self.group_name = f"org_{org_id}"

        # Join the organization's broadcast group
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        logger.info(f"WebSocket connected: org={org_id}")

    async def disconnect(self, close_code):
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        """
        Clients can send ping messages to keep the connection alive.
        We don't currently support client→server commands, but the
        structure is here for future use (e.g. "subscribe to asset X only").
        """
        try:
            data = json.loads(text_data)
            if data.get("type") == "ping":
                await self.send(text_data=json.dumps({"type": "pong"}))
        except json.JSONDecodeError:
            pass

    # --- Channel layer event handlers ---
    # Method name format: {type.with_underscores}
    # Matches the "type" key in group_send payloads

    async def asset_risk_updated(self, event: dict):
        """Receives broadcast from rescore_and_broadcast_asset task."""
        await self.send(text_data=json.dumps({
            "type": "asset.risk_updated",
            "data": {
                "asset_id": event["asset_id"],
                "asset_name": event["asset_name"],
                "risk_score": event["risk_score"],
                "critical_count": event["critical_count"],
                "high_count": event["high_count"],
                "timestamp": event["timestamp"],
            }
        }))

    def _get_token_from_scope(self) -> str | None:
        """Parse JWT from WebSocket query string: ?token=eyJ..."""
        query_string = self.scope.get("query_string", b"").decode()
        params = dict(
            part.split("=", 1)
            for part in query_string.split("&")
            if "=" in part
        )
        return params.get("token")

    @database_sync_to_async
    def _validate_token(self, token: str | None) -> str | None:
        """
        Validate JWT and return organization_id, or None if invalid.
        Uses the same simplejwt machinery as the REST API.
        """
        if not token:
            return None
        try:
            from rest_framework_simplejwt.tokens import AccessToken
            decoded = AccessToken(token)
            return decoded.get("organization_id")
        except Exception:
            return None