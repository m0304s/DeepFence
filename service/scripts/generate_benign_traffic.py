"""로컬 benign 트래픽 생성 스크립트."""

from __future__ import annotations

import argparse
import socket
import subprocess
import time
import urllib.request
import urllib.error


DEFAULT_HTTP_URLS = (
    "https://example.com",
    "https://www.cloudflare.com",
    "https://www.google.com",
)

DEFAULT_DNS_HOSTS = (
    "google.com",
    "naver.com",
    "cloudflare.com",
)

DEFAULT_PING_TARGET = "8.8.8.8"


def send_http_requests(repeat: int, delay: float) -> None:
    """HTTP 요청 반복."""
    for index in range(repeat):
        target = DEFAULT_HTTP_URLS[index % len(DEFAULT_HTTP_URLS)]
        try:
            with urllib.request.urlopen(target, timeout=5) as response:
                response.read(256)
            print(f"[HTTP] 요청 완료: {target}")
        except (urllib.error.URLError, TimeoutError) as error:
            print(f"[HTTP] 요청 실패: {target} ({error})")
        time.sleep(delay)


def send_dns_queries(repeat: int, delay: float) -> None:
    """DNS 조회 반복."""
    for index in range(repeat):
        host = DEFAULT_DNS_HOSTS[index % len(DEFAULT_DNS_HOSTS)]
        try:
            socket.gethostbyname(host)
            print(f"[DNS] 조회 완료: {host}")
        except socket.gaierror as error:
            print(f"[DNS] 조회 실패: {host} ({error})")
        time.sleep(delay)


def send_ping_requests(repeat: int, delay: float) -> None:
    """ping 요청 반복."""
    for _ in range(repeat):
        subprocess.run(
            ["ping", DEFAULT_PING_TARGET, "-n", "1"],
            check=False,
            capture_output=True,
            text=True,
        )
        print(f"[PING] 요청 완료: {DEFAULT_PING_TARGET}")
        time.sleep(delay)


def build_parser() -> argparse.ArgumentParser:
    """인자 파서 생성."""
    parser = argparse.ArgumentParser(description="DeepFence 검증용 benign 트래픽 생성")
    parser.add_argument("--http", action="store_true", help="HTTP 요청 생성")
    parser.add_argument("--dns", action="store_true", help="DNS 조회 생성")
    parser.add_argument("--ping", action="store_true", help="ping 요청 생성")
    parser.add_argument("--repeat", type=int, default=5, help="반복 횟수")
    parser.add_argument("--delay", type=float, default=0.5, help="요청 간 대기 시간(초)")
    return parser


def main() -> None:
    """benign 트래픽 생성 실행."""
    parser = build_parser()
    args = parser.parse_args()

    if not any((args.http, args.dns, args.ping)):
        args.http = True
        args.dns = True
        args.ping = True

    print("benign 트래픽 생성 시작")
    if args.http:
        send_http_requests(args.repeat, args.delay)
    if args.dns:
        send_dns_queries(args.repeat, args.delay)
    if args.ping:
        send_ping_requests(args.repeat, args.delay)
    print("benign 트래픽 생성 완료")


if __name__ == "__main__":
    main()
