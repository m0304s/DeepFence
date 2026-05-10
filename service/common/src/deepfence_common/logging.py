"""런타임 공용 로깅 도우미."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Iterator

_flow_id_var: ContextVar[str] = ContextVar("flow_id", default="-")
_src_var: ContextVar[str] = ContextVar("src", default="-")
_dst_var: ContextVar[str] = ContextVar("dst", default="-")
_action_var: ContextVar[str] = ContextVar("action", default="-")
_risk_score_var: ContextVar[str] = ContextVar("risk_score", default="-")


class _ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.flow_id = _flow_id_var.get()
        record.src = _src_var.get()
        record.dst = _dst_var.get()
        record.action = _action_var.get()
        record.risk_score = _risk_score_var.get()
        return True


_configured = False


def configure_logging(name: str) -> logging.Logger:
    """기본 포맷 로거 반환."""
    global _configured
    if not _configured:
        root = logging.getLogger()
        root.setLevel(logging.INFO)
        if not root.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)s [%(name)s] "
                    "[flow=%(flow_id)s src=%(src)s dst=%(dst)s action=%(action)s risk=%(risk_score)s] "
                    "%(message)s"
                )
            )
            handler.addFilter(_ContextFilter())
            root.addHandler(handler)
        else:
            for handler in root.handlers:
                handler.addFilter(_ContextFilter())
        _configured = True
    return logging.getLogger(name)


@contextmanager
def log_context(
    *,
    flow_id: str = "-",
    src: str = "-",
    dst: str = "-",
    action: str = "-",
    risk_score: str | int = "-",
) -> Iterator[None]:
    """로그 문맥(MDC 유사) 범위 설정."""
    tokens: list[tuple[ContextVar[str], Token[str]]] = [
        (_flow_id_var, _flow_id_var.set(flow_id)),
        (_src_var, _src_var.set(src)),
        (_dst_var, _dst_var.set(dst)),
        (_action_var, _action_var.set(str(action))),
        (_risk_score_var, _risk_score_var.set(str(risk_score))),
    ]
    try:
        yield
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)
