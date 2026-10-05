"""Shared session store — lets the agent chain tool outputs via scan_token.

Sessions are per-process and in-memory. Nothing is persisted, nothing leaves
the machine.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


@dataclass
class Session:
    token: str
    created: float = field(default_factory=time.time)
    hosts: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def touch(self, **updates: Any) -> None:
        for key, value in updates.items():
            if key == "hosts":
                for host in value:
                    if host not in self.hosts:
                        self.hosts.append(host)
            elif key == "urls":
                for url in value:
                    if url not in self.urls:
                        self.urls.append(url)
            else:
                self.meta[key] = value


class SessionStore:
    """In-memory token → session map. Bounded; oldest sessions age out."""

    def __init__(self, max_sessions: int = 512, ttl_seconds: int = 86400) -> None:
        self._sessions: dict[str, Session] = {}
        self._max = max_sessions
        self._ttl = ttl_seconds

    def new(self, **initial: Any) -> Session:
        if len(self._sessions) >= self._max:
            self._evict()
        session = Session(token=str(uuid.uuid4())[:8])
        session.touch(**initial)
        self._sessions[session.token] = session
        return session

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        session = self._sessions.get(token)
        if session is None:
            return None
        if time.time() - session.created > self._ttl:
            del self._sessions[token]
            return None
        return session

    def resolve_targets(
        self, from_token: str | None, explicit: list[str] | None
    ) -> list[str]:
        """Merge explicit targets with everything a prior session discovered."""
        targets = list(explicit or [])
        session = self.get(from_token)
        if session:
            targets.extend(session.urls or session.hosts)
        # de-dupe, preserve order
        seen: set[str] = set()
        unique: list[str] = []
        for t in targets:
            if t and t not in seen:
                seen.add(t)
                unique.append(t)
        return unique

    def _evict(self) -> None:
        oldest = min(self._sessions.values(), key=lambda s: s.created, default=None)
        if oldest:
            self._sessions.pop(oldest.token, None)


store = SessionStore()
