from __future__ import annotations

import io
import logging
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import threading
import uuid

import docker
from docker.errors import APIError, DockerException, NotFound
from docker.models.containers import Container

from cairn.dispatcher.config import ContainerConfig
from cairn.dispatcher.runtime.process import ManagedProcess

LOG = logging.getLogger(__name__)
TRAFFIC_CONTAINER_ROOT = "/home/kali/workspace/.cairn/traffic"
TRAFFIC_ADDON_PATH = "/tmp/cairn-traffic-addon.py"
TRAFFIC_ADDON_SCRIPT = r"""from __future__ import annotations
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import uuid

from mitmproxy import http

TRAFFIC_DIR = Path(os.environ["CAIRN_TRAFFIC_DIR"])
RECORDS_DIR = TRAFFIC_DIR / "records"
INDEX_FILE = TRAFFIC_DIR / "index.jsonl"
PCAP_FILE = "traffic/capture.pcap"

RECORDS_DIR.mkdir(parents=True, exist_ok=True)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _body_to_text(body: bytes | None) -> str:
    if not body:
        return ""
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return body.decode("latin-1", errors="replace")


def _raw_request(flow: http.HTTPFlow) -> str:
    request = flow.request
    head = [f"{request.method} {request.pretty_url} HTTP/1.1"]
    for key, value in request.headers.items(multi=True):
        head.append(f"{key}: {value}")
    return "\r\n".join(head) + "\r\n\r\n" + _body_to_text(request.raw_content)


def _raw_response(flow: http.HTTPFlow) -> str | None:
    response = flow.response
    if response is None:
        return None
    head = [f"HTTP/1.1 {response.status_code} {response.reason}"]
    for key, value in response.headers.items(multi=True):
        head.append(f"{key}: {value}")
    return "\r\n".join(head) + "\r\n\r\n" + _body_to_text(response.raw_content)


def _write_record(flow: http.HTTPFlow) -> None:
    record_id = flow.metadata.get("cairn_traffic_id")
    if not record_id:
        record_id = uuid.uuid4().hex[:16]
        flow.metadata["cairn_traffic_id"] = record_id
    response = flow.response
    payload = {
        "id": record_id,
        "timestamp": _now(),
        "scheme": flow.request.scheme,
        "host": flow.request.host,
        "port": flow.request.port,
        "method": flow.request.method,
        "path": flow.request.path,
        "url": flow.request.pretty_url,
        "status_code": response.status_code if response is not None else None,
        "request_headers": dict(flow.request.headers.items(multi=False)),
        "response_headers": dict(response.headers.items(multi=False)) if response is not None else {},
        "raw_request": _raw_request(flow),
        "raw_response": _raw_response(flow),
        "pcap_file": PCAP_FILE,
        "source_file": f"traffic/records/{record_id}.json",
    }
    record_path = RECORDS_DIR / f"{record_id}.json"
    record_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    with INDEX_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def response(flow: http.HTTPFlow) -> None:
    _write_record(flow)


def error(flow: http.HTTPFlow) -> None:
    _write_record(flow)
"""


class ContainerManager:
    _PREFIX = "cairn-dispatch-"
    _STARTUP_PREFIX = "cairn-startup-healthcheck-"

    def __init__(self, config: ContainerConfig):
        self._config = config
        self._client = docker.from_env()
        self._ensure_running_locks: dict[str, threading.Lock] = {}
        self._ensure_running_locks_guard = threading.Lock()

    def close(self) -> None:
        self._client.close()

    def container_name(self, project_id: str) -> str:
        sanitized = project_id.replace("/", "-")
        return f"{self._PREFIX}{sanitized}"

    def ensure_running(self, project_id: str) -> str:
        name = self.container_name(project_id)
        with self._ensure_running_lock(name):
            return self._ensure_running_locked(project_id, name)

    def _ensure_running_locked(self, project_id: str, name: str) -> str:
        state = self.inspect_state(name)
        if state == "running":
            LOG.debug("container already running project=%s container=%s", project_id, name)
            return name
        if state is not None:
            LOG.info("starting existing container project=%s container=%s state=%s", project_id, name, state)
            self._start_existing(name)
            return name
        LOG.info("creating container project=%s container=%s image=%s", project_id, name, self._config.image)
        try:
            self._client.containers.run(
                self._config.image,
                ["sleep", "infinity"],
                detach=True,
                name=name,
                network_mode=self._config.network_mode,
                cap_add=self._config.cap_add or None,
            )
            LOG.info("created container project=%s container=%s", project_id, name)
            return name
        except APIError as exc:
            if not self._is_name_conflict(exc):
                raise RuntimeError(f"failed to create container {name}: {exc}") from exc
        LOG.info("container name conflict, reusing existing container project=%s container=%s", project_id, name)
        state = self.inspect_state(name)
        if state == "running":
            return name
        if state is not None:
            LOG.info("starting conflicted existing container project=%s container=%s state=%s", project_id, name, state)
            self._start_existing(name)
            return name
        raise RuntimeError(f"failed to create container {name}")

    def _ensure_running_lock(self, name: str) -> threading.Lock:
        with self._ensure_running_locks_guard:
            lock = self._ensure_running_locks.get(name)
            if lock is None:
                lock = threading.Lock()
                self._ensure_running_locks[name] = lock
            return lock

    def create_startup_container(self) -> str:
        name = f"{self._STARTUP_PREFIX}{uuid.uuid4().hex[:12]}"
        LOG.debug("creating startup healthcheck container container=%s image=%s", name, self._config.image)
        try:
            self._client.containers.run(
                self._config.image,
                ["sleep", "infinity"],
                detach=True,
                name=name,
                network_mode=self._config.network_mode,
                cap_add=self._config.cap_add or None,
            )
        except DockerException as exc:
            raise RuntimeError(f"failed to create startup container {name}: {exc}") from exc
        return name

    def inspect_state(self, name: str) -> str | None:
        container = self._get_container(name)
        if container is None:
            return None
        try:
            container.reload()
        except DockerException as exc:
            raise RuntimeError(f"failed to inspect container {name}: {exc}") from exc
        state = container.attrs.get("State", {}).get("Status")
        return str(state) if state else None

    def cleanup_completed(self, project_id: str) -> bool:
        name = self.container_name(project_id)
        state = self.inspect_state(name)
        if state is None:
            return True
        container = self._require_container(name)
        if self._config.completed_action == "remove":
            LOG.info("removing completed project container project=%s container=%s", project_id, name)
            try:
                container.remove(force=True)
            except NotFound:
                return True
            except DockerException as exc:
                LOG.warning("failed to remove container=%s error=%s", name, exc)
                return False
            return self.inspect_state(name) is None
        elif state == "running":
            LOG.info("stopping completed project container project=%s container=%s", project_id, name)
            try:
                container.stop(timeout=1)
            except NotFound:
                return True
            except DockerException as exc:
                LOG.warning("failed to stop container=%s error=%s", name, exc)
                return False
            return self.inspect_state(name) != "running"
        return True

    def cleanup_stopped(self, project_id: str) -> bool:
        name = self.container_name(project_id)
        state = self.inspect_state(name)
        if state != "running":
            return True
        LOG.info("stopping stopped project container project=%s container=%s", project_id, name)
        container = self._require_container(name)
        try:
            container.stop(timeout=1)
        except NotFound:
            return True
        except DockerException as exc:
            LOG.warning("failed to stop stopped project container=%s error=%s", name, exc)
            return False
        return self.inspect_state(name) != "running"

    def cleanup_orphan(self, name: str) -> bool:
        state = self.inspect_state(name)
        if state is None:
            return True
        LOG.info("removing orphan project container container=%s state=%s", name, state)
        container = self._require_container(name)
        try:
            container.remove(force=True)
        except NotFound:
            return True
        except DockerException as exc:
            LOG.warning("failed to remove orphan container=%s error=%s", name, exc)
            return False
        return self.inspect_state(name) is None

    def managed_container_names(self) -> list[str]:
        try:
            containers = self._client.containers.list(all=True)
        except DockerException as exc:
            LOG.warning("failed to list managed containers error=%s", exc)
            return []
        return sorted(container.name for container in containers if container.name.startswith(self._PREFIX))

    def needs_completed_cleanup(self, project_id: str) -> bool:
        name = self.container_name(project_id)
        state = self.inspect_state(name)
        if state is None:
            return False
        if self._config.completed_action == "remove":
            return True
        return state == "running"

    def needs_orphan_cleanup(self, name: str) -> bool:
        return self.inspect_state(name) is not None

    def needs_stopped_cleanup(self, project_id: str) -> bool:
        return self.inspect_state(self.container_name(project_id)) == "running"

    def build_exec_process(
        self,
        container_name: str,
        env: dict[str, str],
        command: list[str],
        timeout_seconds: int | None = None,
        kill_after_seconds: int = 5,
    ) -> ManagedProcess:
        container = self._require_container(container_name)
        argv: list[str] = []
        if timeout_seconds is not None:
            argv.extend(
                [
                    "timeout",
                    "-k",
                    f"{kill_after_seconds}s",
                    f"{timeout_seconds}s",
                ]
            )
        argv.extend(command)
        return ManagedProcess(container, argv, env)

    def traffic_proxy_env(self) -> dict[str, str]:
        if not self._config.traffic_enabled:
            return {}
        proxy = f"http://{self._config.traffic_proxy_host}:{self._config.traffic_proxy_port}"
        ca_cert = "/home/kali/.mitmproxy/mitmproxy-ca-cert.pem"
        return {
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "ALL_PROXY": proxy,
            "http_proxy": proxy,
            "https_proxy": proxy,
            "all_proxy": proxy,
            "NO_PROXY": "127.0.0.1,localhost,cairn-server",
            "no_proxy": "127.0.0.1,localhost,cairn-server",
            "REQUESTS_CA_BUNDLE": ca_cert,
            "CURL_CA_BUNDLE": ca_cert,
            "SSL_CERT_FILE": ca_cert,
            "GIT_SSL_CAINFO": ca_cert,
            "NODE_EXTRA_CA_CERTS": ca_cert,
        }

    def ensure_project_traffic_capture(self, project_id: str, container_name: str) -> None:
        if not self._config.traffic_enabled:
            return
        self.write_text_file(container_name, TRAFFIC_ADDON_PATH, TRAFFIC_ADDON_SCRIPT)
        command = f"""
set -eu
mkdir -p "{TRAFFIC_CONTAINER_ROOT}/records"
if [ ! -f "{TRAFFIC_CONTAINER_ROOT}/mitm.pid" ] || ! kill -0 "$(cat "{TRAFFIC_CONTAINER_ROOT}/mitm.pid")" 2>/dev/null; then
  CAIRN_TRAFFIC_DIR="{TRAFFIC_CONTAINER_ROOT}" nohup mitmdump --listen-host "{self._config.traffic_proxy_host}" --listen-port "{self._config.traffic_proxy_port}" -s "{TRAFFIC_ADDON_PATH}" >"{TRAFFIC_CONTAINER_ROOT}/mitmdump.log" 2>&1 &
  echo $! > "{TRAFFIC_CONTAINER_ROOT}/mitm.pid"
  sleep 2
fi
if command -v tcpdump >/dev/null 2>&1; then
  if [ ! -f "{TRAFFIC_CONTAINER_ROOT}/tcpdump.pid" ] || ! kill -0 "$(cat "{TRAFFIC_CONTAINER_ROOT}/tcpdump.pid")" 2>/dev/null; then
    nohup tcpdump -U -i any -s 0 -w "{TRAFFIC_CONTAINER_ROOT}/capture.pcap" >"{TRAFFIC_CONTAINER_ROOT}/tcpdump.log" 2>&1 &
    echo $! > "{TRAFFIC_CONTAINER_ROOT}/tcpdump.pid"
  fi
fi
"""
        container = self._require_container(container_name)
        result = container.exec_run(["/bin/sh", "-lc", command], stdout=False, stderr=True)
        exit_code = result.exit_code if hasattr(result, "exit_code") else 0
        if exit_code not in (0, None):
            raise RuntimeError(f"failed to start traffic capture for project {project_id}")

    def write_text_file(self, container_name: str, path: str, content: str) -> None:
        archive_path, archive = self._text_file_archive(path, content)
        container = self._require_container(container_name)
        try:
            ok = container.put_archive(archive_path, archive)
        except DockerException as exc:
            raise RuntimeError(f"failed to write container file {path}: {exc}") from exc
        if not ok:
            raise RuntimeError(f"failed to write container file {path}")

    def copy_file_to_host(self, container_name: str, source_path: str, host_path: Path) -> bool:
        target = self._validated_container_path(source_path)
        container = self._require_container(container_name)
        try:
            stream, _stat = container.get_archive(str(target))
        except NotFound:
            return False
        except APIError as exc:
            status_code = getattr(getattr(exc, "response", None), "status_code", None)
            if status_code == 404:
                return False
            raise RuntimeError(f"failed to read container file {source_path}: {exc}") from exc
        except DockerException as exc:
            raise RuntimeError(f"failed to read container file {source_path}: {exc}") from exc

        payload = b"".join(stream)
        data = self._extract_file_from_archive(payload)
        if data is None:
            return False

        destination = Path(host_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        return True

    def copy_path_to_host(self, container_name: str, source_path: str, host_path: Path) -> bool:
        target = self._validated_container_path(source_path)
        container = self._require_container(container_name)
        try:
            stream, _stat = container.get_archive(str(target))
        except NotFound:
            return False
        except APIError as exc:
            status_code = getattr(getattr(exc, "response", None), "status_code", None)
            if status_code == 404:
                return False
            raise RuntimeError(f"failed to read container path {source_path}: {exc}") from exc
        except DockerException as exc:
            raise RuntimeError(f"failed to read container path {source_path}: {exc}") from exc

        payload = b"".join(stream)
        destination = Path(host_path)
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir(parents=True, exist_ok=True)
        self._extract_archive_to_directory(payload, destination)
        return True

    def remove_container(self, name: str, *, force: bool = True) -> None:
        container = self._get_container(name)
        if container is None:
            return
        try:
            container.remove(force=force)
        except NotFound:
            return
        except DockerException as exc:
            LOG.warning("failed to remove container=%s error=%s", name, exc)

    def _start_existing(self, name: str) -> None:
        LOG.debug("starting container=%s", name)
        container = self._require_container(name)
        try:
            container.start()
            return
        except DockerException as exc:
            if self.inspect_state(name) == "running":
                return
            raise RuntimeError(f"failed to start container {name}: {exc}") from exc

    def _get_container(self, name: str) -> Container | None:
        try:
            return self._client.containers.get(name)
        except NotFound:
            return None
        except DockerException as exc:
            raise RuntimeError(f"failed to get container {name}: {exc}") from exc

    def _require_container(self, name: str) -> Container:
        container = self._get_container(name)
        if container is None:
            raise RuntimeError(f"container not found: {name}")
        return container

    @staticmethod
    def _is_name_conflict(exc: APIError) -> bool:
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        explanation = str(getattr(exc, "explanation", "") or exc)
        return status_code == 409 or "is already in use" in explanation

    @staticmethod
    def _validated_container_path(path: str) -> PurePosixPath:
        target = PurePosixPath(path)
        if not target.is_absolute() or target.name in ("", ".", ".."):
            raise ValueError(f"container file path must be absolute: {path}")
        parts = target.parts[1:]
        if not parts or any(part in ("", ".", "..") for part in parts):
            raise ValueError(f"invalid container file path: {path}")
        return target

    @staticmethod
    def _extract_file_from_archive(payload: bytes) -> bytes | None:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                return extracted.read()
        return None

    @staticmethod
    def _extract_archive_to_directory(payload: bytes, destination: Path) -> None:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            members = archive.getmembers()
            prefixes = []
            for member in members:
                parts = PurePosixPath(member.name).parts
                if parts:
                    prefixes.append(parts[0])
            strip_prefix = prefixes[0] if prefixes and all(prefix == prefixes[0] for prefix in prefixes) else None
            for member in members:
                parts = list(PurePosixPath(member.name).parts)
                if strip_prefix and parts and parts[0] == strip_prefix:
                    parts = parts[1:]
                if not parts:
                    continue
                if any(part in ("", ".", "..") for part in parts):
                    continue
                target = destination.joinpath(*parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                target.write_bytes(extracted.read())

    @staticmethod
    def _text_file_archive(path: str, content: str) -> tuple[str, bytes]:
        target = ContainerManager._validated_container_path(path)
        parts = target.parts[1:]
        if len(parts) == 1:
            archive_path = "/"
            archive_parts = parts
        else:
            archive_path = f"/{parts[0]}"
            archive_parts = parts[1:]

        payload = content.encode("utf-8")
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            parent = ""
            for part in archive_parts[:-1]:
                parent = f"{parent}/{part}" if parent else part
                info = tarfile.TarInfo(parent)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)

            file_name = "/".join(archive_parts)
            info = tarfile.TarInfo(file_name)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))
        return archive_path, stream.getvalue()
