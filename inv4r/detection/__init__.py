"""Detection package — data-driven, no vendor code in this package."""

from inv4r.detection.universal import DetectionResult, detect, detect_file, detect_format, detect_vendor

__all__ = ["DetectionResult", "detect", "detect_file", "detect_format", "detect_vendor"]
