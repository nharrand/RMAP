"""
Shared logging setup for rmap.

Design:
  - The library never configures logging globally and never prints to
    stdout on its own initiative - by default the 'rmap' logger has a
    NullHandler attached, so it's silent unless the host application
    configures logging itself (standard library best practice).
  - Every class that talks about "verbose" behavior accepts an optional
    `logger=` argument. If you pass your own `logging.Logger` (e.g.
    `app.logger` from a Flask app), rmap will log through it and you
    have full control of formatting/handlers/levels.
  - If you don't pass a logger AND you set `verbose=True`, rmap will
    attach a simple console handler to its own logger so you get
    reasonable output out of the box for quick scripts / class demos.
"""

import logging

_LIBRARY_LOGGER_NAME = "rmap"

_library_logger = logging.getLogger(_LIBRARY_LOGGER_NAME)
_library_logger.addHandler(logging.NullHandler())


def get_logger(logger: "logging.Logger | None" = None, verbose: bool = False) -> logging.Logger:
    """
    Return the logger a component should use.

    - If `logger` is provided, it is returned as-is (caller stays in
      full control of handlers/levels/formatting).
    - Otherwise, the shared 'rmap' logger is returned. If `verbose` is
      True and that logger has no handlers configured yet (besides the
      default NullHandler), a simple console handler is attached at
      INFO level.
    """
    if logger is not None:
        return logger

    if verbose:
        has_real_handler = any(
            not isinstance(h, logging.NullHandler) for h in _library_logger.handlers
        )
        if not has_real_handler:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("[rmap] %(levelname)s: %(message)s"))
            _library_logger.addHandler(handler)
            _library_logger.setLevel(logging.INFO)

    return _library_logger
