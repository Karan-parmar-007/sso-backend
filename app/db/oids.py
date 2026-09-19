"""Mongo identity helpers — use only default `_id` (ObjectId)."""

from typing import Any

from bson import ObjectId
from bson.errors import InvalidId


def to_object_id(value: str | ObjectId) -> ObjectId:
    if isinstance(value, ObjectId):
        return value
    try:
        return ObjectId(value)
    except (InvalidId, TypeError) as e:
        raise ValueError("Invalid id") from e


def id_str(doc_or_id: Any) -> str:
    """String form of a document `_id` or an ObjectId/str id."""
    if isinstance(doc_or_id, dict):
        return str(doc_or_id["_id"])
    return str(doc_or_id)
