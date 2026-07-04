from __future__ import annotations

from collections.abc import Mapping
from html import escape as html_escape

from .export_models import CYCLONEDX_NAMESPACE


class _XmlElement:
    def __init__(
        self,
        tag: str,
        attributes: Mapping[str, str] | None = None,
    ) -> None:
        self.tag = tag
        self.attributes = dict(attributes or {})
        self.children: list[_XmlElement] = []
        self.text: str | None = None


class _XmlTree:
    """Minimal serializer-only XML tree for deterministic CycloneDX output."""

    @staticmethod
    def Element(
        tag: str,
        attributes: Mapping[str, str] | None = None,
    ) -> _XmlElement:
        return _XmlElement(tag, attributes)

    @staticmethod
    def SubElement(
        parent: _XmlElement,
        tag: str,
        attributes: Mapping[str, str] | None = None,
    ) -> _XmlElement:
        element = _XmlElement(tag, attributes)
        parent.children.append(element)
        return element

    @staticmethod
    def serialize(
        element: _XmlElement,
        *,
        namespace: str = CYCLONEDX_NAMESPACE,
    ) -> str:
        document = _serialize_xml_element(
            element,
            level=0,
            is_root=True,
            namespace=namespace,
        )
        return "<?xml version='1.0' encoding='utf-8'?>\n" + document


def _xml_tag(name: str, *, namespace: str = CYCLONEDX_NAMESPACE) -> str:
    return f"{{{namespace}}}{name}"


def _xml_text(
    parent: _XmlElement,
    name: str,
    value: str,
    *,
    namespace: str = CYCLONEDX_NAMESPACE,
) -> None:
    element = _XmlTree.SubElement(parent, _xml_tag(name, namespace=namespace))
    element.text = value


def _xml_properties(
    parent: _XmlElement,
    properties: object,
    *,
    namespace: str = CYCLONEDX_NAMESPACE,
) -> None:
    if not isinstance(properties, list) or not properties:
        return
    properties_element = _XmlTree.SubElement(
        parent,
        _xml_tag("properties", namespace=namespace),
    )
    for item in properties:
        if not isinstance(item, Mapping):
            continue
        property_element = _XmlTree.SubElement(
            properties_element,
            _xml_tag("property", namespace=namespace),
            {"name": str(item.get("name") or "trustcheck:property")},
        )
        property_element.text = str(item.get("value") or "")


def _serialize_xml_element(
    element: _XmlElement,
    *,
    level: int,
    is_root: bool,
    namespace: str,
) -> str:
    indentation = "  " * level
    tag = _xml_local_name(element.tag)
    attributes = dict(element.attributes)
    if is_root:
        attributes = {"xmlns": namespace, **attributes}
    rendered_attributes = "".join(
        f' {name}="{_xml_escape(value, attribute=True)}"'
        for name, value in attributes.items()
    )
    if not element.children:
        if element.text is None:
            return f"{indentation}<{tag}{rendered_attributes} />"
        return (
            f"{indentation}<{tag}{rendered_attributes}>"
            f"{_xml_escape(element.text)}</{tag}>"
        )
    children = "\n".join(
        _serialize_xml_element(
            child,
            level=level + 1,
            is_root=False,
            namespace=namespace,
        )
        for child in element.children
    )
    text = _xml_escape(element.text) if element.text is not None else ""
    return (
        f"{indentation}<{tag}{rendered_attributes}>{text}\n"
        f"{children}\n"
        f"{indentation}</{tag}>"
    )


def _xml_local_name(tag: str) -> str:
    if tag.startswith("{"):
        _, _, local_name = tag.partition("}")
        return local_name
    return tag


def _xml_escape(value: object, *, attribute: bool = False) -> str:
    sanitized = "".join(
        character
        for character in str(value)
        if _is_xml_character(ord(character))
    )
    return html_escape(sanitized, quote=attribute)


def _is_xml_character(codepoint: int) -> bool:
    return (
        codepoint in {0x09, 0x0A, 0x0D}
        or 0x20 <= codepoint <= 0xD7FF
        or 0xE000 <= codepoint <= 0xFFFD
        or 0x10000 <= codepoint <= 0x10FFFF
    )
