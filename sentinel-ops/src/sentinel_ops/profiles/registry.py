"""Profile loader and in-memory registry resolving built-in and external YAML/JSON profiles."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional
import yaml

from sentinel_ops.profiles.schema import SystemProfile


logger = logging.getLogger(__name__)
BUNDLED_PROFILES_DIR = Path(__file__).resolve().parent / "bundled"
PROFILES_DIR = Path(__file__).resolve().parents[3] / "profiles"
_PROFILE_CACHE: Dict[str, SystemProfile] = {}


def load_profile_file(path: Path) -> SystemProfile:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Profile file '{path}' must deserialize to a mapping.")
    profile = SystemProfile(**data)
    _PROFILE_CACHE[profile.profile_id] = profile
    return profile


def _ensure_builtin_profiles_loaded() -> None:
    for directory in (BUNDLED_PROFILES_DIR, PROFILES_DIR):
        if directory.exists():
            for pfile in sorted(directory.glob("*.y*ml")):
                try:
                    load_profile_file(pfile)
                except Exception as exc:
                    logger.warning("Skipping invalid profile file %s: %s", pfile, exc)
                    continue


def list_profiles() -> List[SystemProfile]:
    _ensure_builtin_profiles_loaded()
    return list(_PROFILE_CACHE.values())


def get_profile(profile_id: Optional[str] = None) -> SystemProfile:
    """Loads a registered profile by ID or file path, defaulting to checkout-demo."""
    pid = profile_id or "checkout-demo"
    if pid in _PROFILE_CACHE:
        return _PROFILE_CACHE[pid]

    candidate_path = Path(pid)
    if candidate_path.is_file():
        return load_profile_file(candidate_path)

    _ensure_builtin_profiles_loaded()
    if pid in _PROFILE_CACHE:
        return _PROFILE_CACHE[pid]

    raise KeyError(f"SystemProfile '{pid}' not found in {PROFILES_DIR} or registry.")
