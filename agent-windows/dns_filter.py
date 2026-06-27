from __future__ import annotations

import socket
import socketserver
import threading
import time
from dataclasses import dataclass
from typing import Callable

from dnslib import A, AAAA, DNSHeader, DNSRecord, QTYPE, RCODE, RR


FALLBACK_UPSTREAM_DNS = ("8.8.8.8", "1.1.1.1")
BLOCK_RESPONSE_TTL = 60
LOG_THROTTLE_SECONDS = 30
LOG_ALLOWED_EVENTS = False

ALLOW_SUFFIXES = (
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "youtube.googleapis.com",
    "youtubei.googleapis.com",
    "googlevideo.com",
    "ytimg.com",
    "ggpht.com",
    "gstatic.com",
    "google.com",
    "googleapis.com",
    "msn.com",
    "bing.com",
    "microsoft.com",
    "microsoftonline.com",
    "live.com",
    "office.com",
    "windows.com",
)

SOCIAL_SUFFIXES = (
    "facebook.com",
    "fb.com",
    "instagram.com",
    "cdninstagram.com",
    "threads.net",
    "tiktok.com",
    "tiktokcdn.com",
    "x.com",
    "twitter.com",
    "twimg.com",
    "snapchat.com",
    "reddit.com",
    "linkedin.com",
    "pinterest.com",
)

ADULT_SUFFIXES = (
    "pornhub.com",
    "xvideos.com",
    "xnxx.com",
    "redtube.com",
    "youporn.com",
    "tube8.com",
    "spankbang.com",
    "xhamster.com",
    "onlyfans.com",
)


@dataclass(frozen=True)
class DomainDecision:
    domain: str
    category: str
    decision: str
    reason: str


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def matches_suffix(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith(f".{suffix}")


def domain_suffixes(domain: str) -> list[str]:
    labels = [label for label in domain.split(".") if label]
    return [".".join(labels[index:]) for index in range(len(labels))]


def classify_domain(domain: str, dynamic_domains: dict[str, str] | None = None) -> DomainDecision:
    return classify_domain_with_keywords(domain, dynamic_domains=dynamic_domains, blocked_keywords=None)


def classify_domain_with_keywords(
    domain: str,
    dynamic_domains: dict[str, str] | None = None,
    blocked_keywords: set[str] | None = None,
) -> DomainDecision:
    normalized = normalize_domain(domain)
    dynamic_domains = dynamic_domains or {}
    blocked_keywords = blocked_keywords or set()

    for suffix in ALLOW_SUFFIXES:
        if matches_suffix(normalized, suffix):
            return DomainDecision(
                domain=normalized,
                category="allowed",
                decision="allowed",
                reason=f"Matched allowlist: {suffix}",
            )

    for suffix in domain_suffixes(normalized):
        category = dynamic_domains.get(suffix)
        if category:
            return DomainDecision(
                domain=normalized,
                category=category,
                decision="blocked",
                reason=f"Matched admin list: {suffix}",
            )

    for keyword in sorted(blocked_keywords):
        if keyword and keyword in normalized:
            return DomainDecision(
                domain=normalized,
                category="keyword",
                decision="blocked",
                reason=f"Matched blocked keyword: {keyword}",
            )

    for suffix in ADULT_SUFFIXES:
        if matches_suffix(normalized, suffix):
            return DomainDecision(
                domain=normalized,
                category="adult",
                decision="blocked",
                reason=f"Matched adult list: {suffix}",
            )

    for suffix in SOCIAL_SUFFIXES:
        if matches_suffix(normalized, suffix):
            return DomainDecision(
                domain=normalized,
                category="social",
                decision="blocked",
                reason=f"Matched social list: {suffix}",
            )

    return DomainDecision(
        domain=normalized,
        category="unknown",
        decision="allowed",
        reason="No local blocklist match",
    )


class DNSFilterServer:
    def __init__(
        self,
        event_callback: Callable[[DomainDecision], None],
        policy_callback: Callable[[str], DomainDecision | None] | None = None,
        upstream_servers: list[str] | None = None,
    ) -> None:
        self.event_callback = event_callback
        self.policy_callback = policy_callback
        self.upstream_servers = upstream_servers or list(FALLBACK_UPSTREAM_DNS)
        self.dynamic_domains: dict[str, str] = {}
        self.blocked_keywords: set[str] = set()
        self._dynamic_domains_lock = threading.Lock()
        self._blocked_keywords_lock = threading.Lock()
        self._servers: list[socketserver.ThreadingUDPServer] = []
        self._thread: threading.Thread | None = None
        self._threads: list[threading.Thread] = []
        self._last_logged: dict[tuple[str, str], float] = {}

    @property
    def is_running(self) -> bool:
        return any(thread.is_alive() for thread in self._threads)

    def start(self) -> None:
        if self.is_running:
            return

        parent = self

        class DNSHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                data, client_socket = self.request
                response = parent.handle_query(data)
                client_socket.sendto(response, self.client_address)

        socketserver.ThreadingUDPServer.allow_reuse_address = True

        class IPv6ThreadingUDPServer(socketserver.ThreadingUDPServer):
            address_family = socket.AF_INET6

        bind_targets: list[tuple[type[socketserver.ThreadingUDPServer], tuple[str, int]]] = [
            (socketserver.ThreadingUDPServer, ("127.0.0.1", 53)),
            (IPv6ThreadingUDPServer, ("::1", 53)),
        ]
        last_error: Exception | None = None

        for server_class, bind_address in bind_targets:
            try:
                server = server_class(bind_address, DNSHandler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                self._servers.append(server)
                self._threads.append(thread)
            except Exception as exc:
                last_error = exc

        if not self._servers:
            raise RuntimeError(f"Could not start DNS filter: {last_error}")

    def stop(self) -> None:
        for server in self._servers:
            server.shutdown()
            server.server_close()
        self._servers = []
        self._threads = []
        self._thread = None

    def update_dynamic_domains(self, domains: dict[str, str]) -> None:
        normalized_domains = {
            normalize_domain(domain): category
            for domain, category in domains.items()
            if normalize_domain(domain)
            and not any(matches_suffix(normalize_domain(domain), suffix) for suffix in ALLOW_SUFFIXES)
        }
        with self._dynamic_domains_lock:
            self.dynamic_domains = normalized_domains

    def update_blocked_keywords(self, keywords: list[str]) -> None:
        normalized_keywords = {
            keyword.strip().lower()
            for keyword in keywords
            if keyword.strip()
        }
        with self._blocked_keywords_lock:
            self.blocked_keywords = normalized_keywords

    def get_dynamic_domains(self) -> dict[str, str]:
        with self._dynamic_domains_lock:
            return dict(self.dynamic_domains)

    def get_blocked_keywords(self) -> set[str]:
        with self._blocked_keywords_lock:
            return set(self.blocked_keywords)

    def handle_query(self, data: bytes) -> bytes:
        try:
            request = DNSRecord.parse(data)
            qname = normalize_domain(str(request.q.qname))
            qtype = QTYPE[request.q.qtype]
            decision = classify_domain_with_keywords(
                qname,
                dynamic_domains=self.get_dynamic_domains(),
                blocked_keywords=self.get_blocked_keywords(),
            )
            if (
                decision.decision == "allowed"
                and decision.category == "unknown"
                and self.policy_callback is not None
            ):
                server_decision = self.policy_callback(qname)
                if server_decision is not None:
                    decision = server_decision

            self.log_decision(decision)

            if decision.decision == "blocked":
                return self.block_response(request, qtype)

            return self.forward_query(data)
        except Exception:
            try:
                request = DNSRecord.parse(data)
                reply = request.reply()
                reply.header.rcode = RCODE.SERVFAIL
                return reply.pack()
            except Exception:
                return DNSRecord(DNSHeader(qr=1, rcode=RCODE.SERVFAIL)).pack()

    def block_response(self, request: DNSRecord, qtype: str) -> bytes:
        reply = request.reply()
        qname = request.q.qname

        if qtype == "A":
            reply.add_answer(RR(qname, QTYPE.A, ttl=BLOCK_RESPONSE_TTL, rdata=A("0.0.0.0")))
        elif qtype == "AAAA":
            reply.add_answer(RR(qname, QTYPE.AAAA, ttl=BLOCK_RESPONSE_TTL, rdata=AAAA("::")))

        return reply.pack()

    def forward_query(self, data: bytes) -> bytes:
        last_error: Exception | None = None

        for upstream_server in self.upstream_servers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                    upstream.settimeout(4)
                    upstream.sendto(data, (upstream_server, 53))
                    response, _ = upstream.recvfrom(4096)
                    return response
            except Exception as exc:
                last_error = exc

        raise RuntimeError(f"All upstream DNS servers failed: {last_error}")

    def log_decision(self, decision: DomainDecision) -> None:
        if decision.decision == "allowed" and not LOG_ALLOWED_EVENTS:
            return

        key = (decision.domain, decision.decision)
        now = time.time()
        previous = self._last_logged.get(key, 0)

        if now - previous < LOG_THROTTLE_SECONDS:
            return

        self._last_logged[key] = now
        threading.Thread(target=self.event_callback, args=(decision,), daemon=True).start()
