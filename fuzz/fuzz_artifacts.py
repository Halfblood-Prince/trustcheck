from __future__ import annotations

import io
import sys
import tarfile
import zipfile

import atheris

with atheris.instrument_imports():
    from trustcheck.artifacts import inspect_artifact


def _structured_zip(data: bytes, *, wheel: bool) -> bytes:
    output = io.BytesIO()
    name = "demo-1.0.dist-info/RECORD" if wheel else "demo-1.0/PKG-INFO"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)
        archive.writestr("demo/payload.py", data[::-1])
    return output.getvalue()


def _structured_tar(data: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo("demo-1.0/PKG-INFO")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def test_one_input(data: bytes) -> None:
    if not data:
        return
    selector = data[0] % 5
    body = data[1:]
    if selector == 0:
        filename, payload = "demo-1.0-py3-none-any.whl", body
    elif selector == 1:
        filename, payload = "demo-1.0-py3-none-any.whl", _structured_zip(body, wheel=True)
    elif selector == 2:
        filename, payload = "demo-1.0.zip", body
    elif selector == 3:
        filename, payload = "demo-1.0.zip", _structured_zip(body, wheel=False)
    else:
        filename, payload = "demo-1.0.tar.gz", _structured_tar(body)
    inspect_artifact(
        filename,
        payload,
        expected_project="demo",
        expected_version="1.0",
    )


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
