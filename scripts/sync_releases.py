#!/usr/bin/env python3
"""Mirror Xray Linux x86_64 binaries into this repository's releases.

Two sources are mirrored:

* the official XTLS/Xray-core releases (binary extracted from Xray-linux-64.zip);
* the Medium1992/Xray-core-fork releases (raw xray-linux-amd64 binary), published
  under tags with the ``fork-`` prefix so they never collide with official tags.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

UPSTREAM_REPOSITORY = "XTLS/Xray-core"
ASSET_NAME = "Xray-linux-64.zip"
BINARY_NAME = "Xray-linux-64"
DIGEST_NAME = f"{ASSET_NAME}.dgst"
FORK_REPOSITORY = "Medium1992/Xray-core-fork"
FORK_ASSET_NAME = "xray-linux-amd64"
FORK_SUMS_NAME = "sha256sums.txt"
FORK_TAG_PREFIX = "fork-"
API_ROOT = "https://api.github.com"
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]*$")
BINARY_SHA_RE = re.compile(r"SHA-256 бинарника: `([0-9a-fA-F]{64})`")
PROVENANCE_RE = re.compile(r"<!-- xray-mirror-provenance:(\{.*?\}) -->")
MAX_ARCHIVE_SIZE = 128 * 1024 * 1024
MAX_DIGEST_SIZE = 64 * 1024
MAX_BINARY_SIZE = 128 * 1024 * 1024
ELF_MAGIC = b"\x7fELF"


@dataclass(frozen=True)
class Source:
    key: str
    repository: str
    tag_prefix: str
    binary_asset: str
    digest_asset: str
    # Names of the provenance fields for the two assets. The official source
    # keeps its historical names so existing releases are not re-synced.
    provenance_names: tuple[str, str]
    name_prefix: str
    make_latest: bool


OFFICIAL = Source(
    key="official",
    repository=UPSTREAM_REPOSITORY,
    tag_prefix="",
    binary_asset=ASSET_NAME,
    digest_asset=DIGEST_NAME,
    provenance_names=("zip", "digest"),
    name_prefix="",
    make_latest=True,
)
FORK = Source(
    key="fork",
    repository=FORK_REPOSITORY,
    tag_prefix=FORK_TAG_PREFIX,
    binary_asset=FORK_ASSET_NAME,
    digest_asset=FORK_SUMS_NAME,
    provenance_names=("binary", "sums"),
    name_prefix="Fork Medium1992: ",
    make_latest=False,
)
SOURCES = (OFFICIAL, FORK)


def version_from_tag(tag: str) -> str:
    version = tag[1:] if tag.startswith("v") else tag
    if not VERSION_RE.fullmatch(version):
        raise ValueError(f"unsafe version derived from tag {tag!r}")
    return version


def destination_tag(upstream_tag: str, source: Source = OFFICIAL) -> str:
    version_from_tag(upstream_tag)
    return f"{source.tag_prefix}{upstream_tag}"


def owns_tag(source: Source, tag: str) -> bool:
    """Whether a destination release tag belongs to this source."""
    if source.tag_prefix:
        return tag.startswith(source.tag_prefix)
    return not any(
        other.tag_prefix and tag.startswith(other.tag_prefix) for other in SOURCES
    )


def asset_by_name(release: dict[str, Any], name: str) -> dict[str, Any] | None:
    return next((asset for asset in release.get("assets", []) if asset.get("name") == name), None)


def is_mirrorable(release: dict[str, Any], source: Source = OFFICIAL) -> bool:
    return (
        not release.get("draft", False)
        and asset_by_name(release, source.binary_asset) is not None
        and asset_by_name(release, source.digest_asset) is not None
    )


def in_scope(
    upstream_releases: list[dict[str, Any]],
    start_published_at: str,
    source: Source = OFFICIAL,
) -> list[dict[str, Any]]:
    """Mirrorable releases inside the configured range, newest first."""
    return sorted(
        (
            release
            for release in upstream_releases
            if is_mirrorable(release, source)
            and (release.get("published_at") or "") >= start_published_at
        ),
        key=lambda release: release["published_at"],
        reverse=True,
    )


def plan_releases(
    upstream_releases: list[dict[str, Any]],
    destination_tags: set[str],
    start_published_at: str,
    source: Source = OFFICIAL,
) -> list[dict[str, Any]]:
    candidates = in_scope(upstream_releases, start_published_at, source)
    if not candidates:
        return []

    # The durable timestamp boundary is the source of truth. Restore every
    # missing in-range release, including when the destination is completely empty.
    missing = [
        release
        for release in candidates
        if destination_tag(release["tag_name"], source) not in destination_tags
    ]
    return list(reversed(missing))


def parse_sha256(digest_text: str) -> str:
    match = re.search(r"^SHA2-256=\s*([0-9a-fA-F]{64})\s*$", digest_text, re.MULTILINE)
    if not match:
        raise ValueError("official digest does not contain SHA2-256")
    return match.group(1).lower()


def parse_sha256sums(sums_text: str, filename: str) -> str:
    """Read the SHA-256 of ``filename`` from a ``sha256sum`` style file."""
    found = [
        match.group(1).lower()
        for match in re.finditer(
            r"^([0-9a-fA-F]{64})[ \t]+\*?(\S+)[ \t]*$", sums_text, re.MULTILINE
        )
        if match.group(2) == filename
    ]
    if len(found) != 1:
        raise ValueError(f"checksum file must list {filename} exactly once")
    return found[0]


def extract_xray(zip_bytes: bytes, expected_sha256: str, version: str, output_dir: Path) -> Path:
    if len(zip_bytes) > MAX_ARCHIVE_SIZE:
        raise ValueError("official archive exceeds size limit")
    actual_sha256 = hashlib.sha256(zip_bytes).hexdigest()
    if actual_sha256 != expected_sha256.lower():
        raise ValueError(
            f"archive SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / BINARY_NAME
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        names = archive.namelist()
        if names.count("xray") != 1:
            raise ValueError("official archive must contain exactly one root entry named 'xray'")
        info = archive.getinfo("xray")
        if info.file_size > MAX_BINARY_SIZE:
            raise ValueError("xray binary exceeds uncompressed size limit")
        binary = archive.read("xray")

    output_path.write_bytes(binary)
    output_path.chmod(0o755)
    return output_path


def verify_fork_binary(binary: bytes, expected_sha256: str) -> str:
    if len(binary) > MAX_BINARY_SIZE:
        raise ValueError("fork binary exceeds size limit")
    if not binary.startswith(ELF_MAGIC):
        raise ValueError("fork binary is not an ELF executable")
    actual_sha256 = hashlib.sha256(binary).hexdigest()
    if actual_sha256 != expected_sha256.lower():
        raise ValueError(
            f"fork binary SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        )
    return actual_sha256


def upstream_provenance(release: dict[str, Any], source: Source = OFFICIAL) -> dict[str, Any]:
    binary_asset = asset_by_name(release, source.binary_asset)
    digest_asset = asset_by_name(release, source.digest_asset)
    if binary_asset is None or digest_asset is None:
        raise ValueError(f"release {release.get('tag_name')} lacks required source assets")
    first, second = source.provenance_names
    provenance: dict[str, Any] = {}
    for name, asset in ((first, binary_asset), (second, digest_asset)):
        provenance[f"{name}_asset_id"] = asset.get("id")
        provenance[f"{name}_asset_digest"] = asset.get("digest")
        provenance[f"{name}_asset_size"] = asset.get("size")
    return provenance


def release_name(release: dict[str, Any], source: Source = OFFICIAL) -> str:
    return f"{source.name_prefix}{release.get('name') or release['tag_name']}"


def build_release_payload(
    release: dict[str, Any], binary_sha256: str, source: Source = OFFICIAL
) -> dict[str, Any]:
    upstream_tag = release["tag_name"]
    tag = destination_tag(upstream_tag, source)
    source_url = release.get(
        "html_url", f"https://github.com/{source.repository}/releases/tag/{upstream_tag}"
    )
    provenance = json.dumps(
        upstream_provenance(release, source), sort_keys=True, separators=(",", ":")
    )
    destination = os.environ.get("GITHUB_REPOSITORY", "PentiumB/xray-binary")
    encoded_tag = urllib.parse.quote(tag, safe="")
    config = {"geodata": {
        "core": {
            "url": f"https://github.com/{destination}/releases/download/{encoded_tag}/{BINARY_NAME}",
            "sha256": binary_sha256,
        },
        "outbound": "direct",
    }}
    snippet = json.dumps(config, indent=2, ensure_ascii=False)
    if source is OFFICIAL:
        intro = (
            "Автоматически извлечённый без изменений файл `xray` из официального "
            f"архива `{ASSET_NAME}`.\n\n"
        )
    else:
        intro = (
            f"Неофициальная сборка форка [{source.repository}](https://github.com/{source.repository}): "
            f"файл `{source.binary_asset}` без изменений, переименован в `{BINARY_NAME}`. "
            f"SHA-256 сверен с `{source.digest_asset}` и digest GitHub API.\n\n"
        )
    payload: dict[str, Any] = {
        "tag_name": tag,
        "name": release_name(release, source),
        "body": (
            intro
            + f"SHA-256 бинарника: `{binary_sha256}`\n\nИсточник: {source_url}\n\n"
            "### Конфигурация Remnawave Node\n\n"
            "Добавьте поле `geodata` в конфигурацию:\n\n"
            f"```json\n{snippet}\n```\n\n"
            f"<!-- xray-mirror-provenance:{provenance} -->"
        ),
        "draft": False,
        "prerelease": bool(release.get("prerelease", False)),
    }
    if not source.make_latest:
        payload["make_latest"] = "false"
    return payload


def release_needs_sync(
    upstream: dict[str, Any], destination: dict[str, Any], source: Source = OFFICIAL
) -> bool:
    version_from_tag(upstream["tag_name"])
    if destination.get("name") != release_name(upstream, source):
        return True
    if bool(destination.get("draft")):
        return True
    if bool(destination.get("prerelease")) != bool(upstream.get("prerelease")):
        return True

    assets = destination.get("assets", [])
    if len(assets) != 1 or assets[0].get("name") != BINARY_NAME:
        return True

    body = destination.get("body") or ""
    binary_match = BINARY_SHA_RE.search(body)
    provenance_match = PROVENANCE_RE.search(body)
    if not binary_match or not provenance_match:
        return True
    try:
        recorded_provenance = json.loads(provenance_match.group(1))
    except json.JSONDecodeError:
        return True
    if recorded_provenance != upstream_provenance(upstream, source):
        return True

    binary_sha256 = binary_match.group(1).lower()
    if body != build_release_payload(upstream, binary_sha256, source)["body"]:
        return True
    expected_digest = f"sha256:{binary_sha256}"
    return (assets[0].get("digest") or "").lower() != expected_digest


class GitHubClient:
    def __init__(self, token: str | None = None) -> None:
        self.token = token

    def request(
        self,
        method: str,
        url: str,
        payload: dict[str, Any] | None = None,
        content_type: str = "application/vnd.github+json",
        raw_body: bytes | None = None,
    ) -> tuple[Any, dict[str, str]]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "PentiumB-xray-binary-mirror",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        hostname = urllib.parse.urlparse(url).hostname
        if self.token and hostname in {"api.github.com", "uploads.github.com"}:
            headers["Authorization"] = f"Bearer {self.token}"

        body = raw_body
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        if body is not None:
            headers["Content-Type"] = content_type

        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                data = response.read()
                response_headers = dict(response.headers.items())
        except urllib.error.HTTPError as error:
            details = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API {method} {url} failed: HTTP {error.code}: {details}") from error

        if not data:
            return None, response_headers
        if "json" in response_headers.get("Content-Type", ""):
            return json.loads(data), response_headers
        return data, response_headers

    def get_json(self, url: str) -> Any:
        return self.request("GET", url)[0]

    def paginate(self, url: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            separator = "&" if "?" in url else "?"
            batch = self.get_json(f"{url}{separator}per_page=100&page={page}")
            if not batch:
                return items
            items.extend(batch)
            if len(batch) < 100:
                return items
            page += 1

    def paginate_releases_since(self, url: str, start_published_at: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            separator = "&" if "?" in url else "?"
            batch = self.get_json(f"{url}{separator}per_page=100&page={page}")
            if not batch:
                return items
            items.extend(batch)
            if len(batch) < 100 or any(
                (release.get("published_at") or "") < start_published_at
                for release in batch
            ):
                return items
            page += 1

    def download(self, url: str) -> bytes:
        data, _ = self.request("GET", url)
        if not isinstance(data, bytes):
            raise TypeError(f"expected binary response from {url}")
        return data


def download_asset(client: GitHubClient, asset: dict[str, Any], max_size: int) -> bytes:
    size = asset.get("size")
    if not isinstance(size, int) or size < 0 or size > max_size:
        raise ValueError(f"asset {asset.get('name')} has invalid size: {size}")
    data = client.download(asset["browser_download_url"])
    if len(data) != size:
        raise ValueError(
            f"asset {asset.get('name')} size mismatch: API says {size}, downloaded {len(data)}"
        )
    api_digest = asset.get("digest")
    if api_digest:
        actual_digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if actual_digest.lower() != api_digest.lower():
            raise ValueError(f"asset {asset.get('name')} does not match GitHub API digest")
    return data


def upload_url(release: dict[str, Any], filename: str) -> str:
    base = release["upload_url"].split("{", 1)[0]
    return f"{base}?{urllib.parse.urlencode({'name': filename})}"


def prepare_binary(
    client: GitHubClient, upstream: dict[str, Any], source: Source = OFFICIAL
) -> tuple[str, bytes, str]:
    tag = upstream["tag_name"]
    version = version_from_tag(tag)
    binary_asset = asset_by_name(upstream, source.binary_asset)
    digest_asset = asset_by_name(upstream, source.digest_asset)
    if binary_asset is None or digest_asset is None:
        raise ValueError(f"release {tag} lacks required source assets")

    digest_text = download_asset(client, digest_asset, MAX_DIGEST_SIZE).decode("utf-8")
    if source is OFFICIAL:
        expected_archive_sha256 = parse_sha256(digest_text)
        archive = download_asset(client, binary_asset, MAX_ARCHIVE_SIZE)
        with tempfile.TemporaryDirectory() as directory:
            binary_path = extract_xray(
                archive, expected_archive_sha256, version, Path(directory)
            )
            binary = binary_path.read_bytes()
        return BINARY_NAME, binary, hashlib.sha256(binary).hexdigest()

    expected_sha256 = parse_sha256sums(digest_text, source.binary_asset)
    binary = download_asset(client, binary_asset, MAX_BINARY_SIZE)
    return BINARY_NAME, binary, verify_fork_binary(binary, expected_sha256)


def ensure_release(
    client: GitHubClient,
    destination: str,
    upstream: dict[str, Any],
    existing: dict[str, Any] | None,
    source: Source = OFFICIAL,
) -> None:
    # Verify and prepare the binary before creating or modifying a public
    # destination release. A failed download or digest check leaves the
    # destination untouched.
    filename, binary, binary_sha256 = prepare_binary(client, upstream, source)
    payload = build_release_payload(upstream, binary_sha256, source)
    tag = payload["tag_name"]

    staging_payload = dict(payload)
    staging_payload["draft"] = True
    if existing is None:
        release, _ = client.request(
            "POST", f"{API_ROOT}/repos/{destination}/releases", payload=staging_payload
        )
        print(f"Created destination draft {tag}")
    else:
        release, _ = client.request(
            "PATCH",
            f"{API_ROOT}/repos/{destination}/releases/{existing['id']}",
            payload=staging_payload,
        )
        print(f"Moved {tag} to draft for safe reconciliation")

    # Enforce exactly one release asset. Existing files are never trusted by
    # name alone: a repair replaces them with the freshly verified binary.
    for asset in release.get("assets", []):
        client.request(
            "DELETE", f"{API_ROOT}/repos/{destination}/releases/assets/{asset['id']}"
        )
        print(f"Deleted existing asset {asset.get('name')} from {tag}")

    client.request(
        "POST",
        upload_url(release, filename),
        content_type="application/octet-stream",
        raw_body=binary,
    )
    client.request(
        "PATCH",
        f"{API_ROOT}/repos/{destination}/releases/{release['id']}",
        payload=payload,
    )

    encoded_tag = urllib.parse.quote(tag, safe="")
    published = client.get_json(
        f"{API_ROOT}/repos/{destination}/releases/tags/{encoded_tag}"
    )
    published_assets = published.get("assets", [])
    if published.get("draft") or bool(published.get("prerelease")) != payload["prerelease"]:
        raise RuntimeError(f"published release {tag} has incorrect release status")
    if len(published_assets) != 1 or published_assets[0].get("name") != filename:
        raise RuntimeError(f"published release {tag} does not contain exactly asset {filename}")
    if (published_assets[0].get("digest") or "").lower() != f"sha256:{binary_sha256}":
        raise RuntimeError(f"published release {tag} asset digest does not match upload")
    print(f"Published and verified {source.key} binary {filename} in {tag}")


def draft_withdrawn_release(
    client: GitHubClient, destination: str, release: dict[str, Any]
) -> None:
    if release.get("draft"):
        return
    client.request(
        "PATCH",
        f"{API_ROOT}/repos/{destination}/releases/{release['id']}",
        payload={"draft": True},
    )
    print(f"Moved withdrawn or incomplete upstream release {release['tag_name']} to draft")


def source_start(state: dict[str, Any], source: Source) -> str | None:
    """The mirror boundary of a source, or None when the source is not enabled."""
    if source is OFFICIAL:
        return state["start_published_at"]
    section = state.get(source.key)
    return section.get("start_published_at") if section else None


def sync_source(
    client: GitHubClient,
    destination: str,
    source: Source,
    start_published_at: str,
    by_tag: dict[str, dict[str, Any]],
) -> bool:
    """Mirror one source. Returns whether anything was changed."""
    upstream_releases = client.paginate_releases_since(
        f"{API_ROOT}/repos/{source.repository}/releases", start_published_at
    )
    upstream_by_tag = {
        destination_tag(release["tag_name"], source): release
        for release in in_scope(upstream_releases, start_published_at, source)
    }
    own = {tag: release for tag, release in by_tag.items() if owns_tag(source, tag)}

    planned = plan_releases(upstream_releases, set(own), start_published_at, source)
    planned_tags = {destination_tag(release["tag_name"], source) for release in planned}
    repairs = [
        upstream
        for tag, upstream in upstream_by_tag.items()
        if tag in own
        and tag not in planned_tags
        and release_needs_sync(upstream, own[tag], source)
    ]
    ordered = planned + sorted(repairs, key=lambda release: release["published_at"])

    for upstream in ordered:
        tag = destination_tag(upstream["tag_name"], source)
        ensure_release(client, destination, upstream, own.get(tag), source)

    withdrawn = [release for tag, release in own.items() if tag not in upstream_by_tag]
    for release in withdrawn:
        draft_withdrawn_release(client, destination, release)

    return bool(ordered or withdrawn)


def main() -> int:
    destination = os.environ.get("GITHUB_REPOSITORY", "PentiumB/xray-binary")
    token = os.environ.get("GITHUB_TOKEN")
    dry_run = os.environ.get("DRY_RUN") == "1"
    if not token and not dry_run:
        print("GITHUB_TOKEN is required", file=sys.stderr)
        return 2

    state_path = Path(__file__).resolve().parents[1] / "mirror-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    sources = [
        (source, start)
        for source in SOURCES
        if (start := source_start(state, source)) is not None
    ]

    client = GitHubClient(token)

    if dry_run:
        for source, start in sources:
            releases = client.paginate_releases_since(
                f"{API_ROOT}/repos/{source.repository}/releases", start
            )
            candidates = in_scope(releases, start, source)
            if not candidates:
                raise RuntimeError(
                    f"no mirrorable {source.key} releases found in configured range"
                )
            latest = candidates[0]
            print(
                json.dumps(
                    {
                        "source": source.key,
                        "tag": destination_tag(latest["tag_name"], source),
                        "prerelease": bool(latest["prerelease"]),
                        "binary_name": BINARY_NAME,
                        "binary_asset": source.binary_asset,
                        "digest_asset": source.digest_asset,
                    },
                    ensure_ascii=False,
                )
            )
        return 0

    destination_releases = client.paginate(f"{API_ROOT}/repos/{destination}/releases")
    by_tag = {release["tag_name"]: release for release in destination_releases}

    changed = False
    for source, start in sources:
        changed = sync_source(client, destination, source, start, by_tag) or changed

    if not changed:
        print("All mirrored releases already match upstream metadata and verified assets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
