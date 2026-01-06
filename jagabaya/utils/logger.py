"""
Structured logging for Jagabaya.

Provides a consistent logging interface with support for:
- Multiple log levels
- Structured JSON logging
- Console and file output
- Rich formatting for console
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text


class LogLevel(str, Enum):
    """Log levels for Jagabaya."""
    
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    
    @property
    def numeric(self) -> int:
        """Get numeric log level."""
        levels = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL,
        }
        return levels.get(self.value, logging.INFO)


# Global logger cache
_loggers: dict[str, logging.Logger] = {}


def get_logger(
    name: str = "jagabaya",
    level: LogLevel | str = LogLevel.INFO,
) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (usually module name)
        level: Log level
    
    Returns:
        Configured logger instance
    """
    if name in _loggers:
        return _loggers[name]
    
    logger = logging.getLogger(name)
    
    # Set level
    if isinstance(level, str):
        level = LogLevel(level.lower())
    logger.setLevel(level.numeric)
    
    # Add handler if none exists
    if not logger.handlers:
        handler = RichHandler(
            console=Console(stderr=True),
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    
    _loggers[name] = logger
    return logger


def setup_logging(
    level: LogLevel | str = LogLevel.INFO,
    log_file: str | Path | None = None,
    json_format: bool = False,
    console: bool = True,
) -> None:
    """
    Set up logging configuration for Jagabaya.
    
    Args:
        level: Minimum log level
        log_file: Optional file path for log output
        json_format: Use JSON format for file logs
        console: Enable console output
    """
    if isinstance(level, str):
        level = LogLevel(level.lower())
    
    # Get root jagabaya logger
    root = logging.getLogger("jagabaya")
    root.setLevel(level.numeric)
    
    # Clear existing handlers
    root.handlers.clear()
    
    # Console handler
    if console:
        console_handler = RichHandler(
            console=Console(stderr=True),
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        console_handler.setLevel(level.numeric)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(console_handler)
    
    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        if json_format:
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
            file_handler.setFormatter(JsonFormatter())
        else:
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
            file_handler.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
            ))
        
        file_handler.setLevel(level.numeric)
        root.addHandler(file_handler)


class JsonFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        import json
        
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add extra fields
        if hasattr(record, "extra"):
            log_data.update(record.extra)
        
        # Add exception info
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


class LogContext:
    """
    Context manager for logging with extra context.
    
    Example:
        >>> with LogContext(logger, action="scan", target="example.com"):
        ...     logger.info("Starting scan")
    """
    
    def __init__(self, logger: logging.Logger, **context: Any):
        """Initialize with logger and context."""
        self.logger = logger
        self.context = context
        self._old_factory = None
    
    def __enter__(self) -> logging.Logger:
        """Enter context."""
        self._old_factory = logging.getLogRecordFactory()
        
        extra = self.context
        
        def record_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
            record = self._old_factory(*args, **kwargs)
            record.extra = extra
            return record
        
        logging.setLogRecordFactory(record_factory)
        return self.logger
    
    def __exit__(self, *args: Any) -> None:
        """Exit context."""
        if self._old_factory:
            logging.setLogRecordFactory(self._old_factory)


def log_tool_execution(
    logger: logging.Logger,
    tool: str,
    target: str,
    success: bool,
    duration: float,
    error: str | None = None,
) -> None:
    """
    Log a tool execution with structured data.
    
    Args:
        logger: Logger to use
        tool: Tool name
        target: Target scanned
        success: Whether execution succeeded
        duration: Duration in seconds
        error: Error message if failed
    """
    if success:
        logger.info(
            f"[magenta]{tool}[/] on [cyan]{target}[/] completed in {duration:.1f}s"
        )
    else:
        logger.error(
            f"[magenta]{tool}[/] on [cyan]{target}[/] failed: {error or 'Unknown error'}"
        )


def log_finding(
    logger: logging.Logger,
    severity: str,
    title: str,
    target: str,
) -> None:
    """
    Log a security finding.
    
    Args:
        logger: Logger to use
        severity: Finding severity
        title: Finding title
        target: Target where found
    """
    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    color = severity_colors.get(severity.lower(), "white")
    
    logger.info(
        f"[{color}][{severity.upper()}][/{color}] {title} @ [cyan]{target}[/]"
    )
