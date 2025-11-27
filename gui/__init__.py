"""GUI package for CryptsaZ.

This file makes the `gui` directory importable as a package. It intentionally
keeps imports lazy to avoid pulling in heavy GUI modules during test discovery.
"""

__all__ = ["core_api", "tk_gui", "simple_gui"]
