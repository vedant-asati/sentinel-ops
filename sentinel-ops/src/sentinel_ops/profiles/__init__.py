"""Versioned system profile contracts and registry for multi-system onboarding."""

from sentinel_ops.profiles.registry import get_profile, list_profiles, load_profile_file
from sentinel_ops.profiles.schema import (
    RulePreflightResult,
    ServiceSpec,
    SignalMapping,
    SystemProfile,
    TraceContract,
)

__all__ = [
    "SystemProfile",
    "ServiceSpec",
    "SignalMapping",
    "TraceContract",
    "RulePreflightResult",
    "get_profile",
    "list_profiles",
    "load_profile_file",
]
