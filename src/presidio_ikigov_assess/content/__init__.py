"""Pluggable regulatory-content packs (v0.16.0) and classification-profile packs (v0.20.0)."""

from __future__ import annotations

from presidio_ikigov_assess.content.builtin import (
    builtin_packs,
    euaiact_pack,
    iso42001_pack,
    nist_ai_rmf_pack,
)
from presidio_ikigov_assess.content.coverage import Coverage, TargetCoverage, evaluate_coverage
from presidio_ikigov_assess.content.loader import (
    content_dir,
    load_external_packs,
    load_external_profile_packs,
    load_packs,
    load_profile_packs,
)
from presidio_ikigov_assess.content.pack import (
    ContentError,
    ContentPack,
    pack_from_dict,
    pack_to_dict,
    validate_pack,
)
from presidio_ikigov_assess.content.profile import (
    CellProfile,
    ProfileError,
    ProfilePack,
    profile_pack_from_dict,
    profile_pack_to_dict,
    validate_profile_pack,
)
from presidio_ikigov_assess.content.profile_builtin import builtin_classification_profile_pack

__all__ = [
    # ContentPack
    "ContentPack",
    "ContentError",
    "Coverage",
    "TargetCoverage",
    "evaluate_coverage",
    "load_packs",
    "load_external_packs",
    "content_dir",
    "builtin_packs",
    "iso42001_pack",
    "euaiact_pack",
    "nist_ai_rmf_pack",
    "pack_from_dict",
    "pack_to_dict",
    "validate_pack",
    # ProfilePack (v0.20.0)
    "CellProfile",
    "ProfilePack",
    "ProfileError",
    "profile_pack_from_dict",
    "profile_pack_to_dict",
    "validate_profile_pack",
    "builtin_classification_profile_pack",
    "load_profile_packs",
    "load_external_profile_packs",
]
