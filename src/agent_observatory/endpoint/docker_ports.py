from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from typing import Any

from .service_exposure import DockerPublishedPort


class DockerCollectionError(RuntimeError):
    """Raised when Docker CLI evidence cannot be collected or parsed safely."""


def _parse_port_key(value: str) -> tuple[int, str]:
    if not isinstance(value, str) or "/" not in value:
        raise DockerCollectionError(f"invalid Docker port key: {value!r}")
    port_text, protocol = value.rsplit("/", 1)
    try:
        port = int(port_text)
    except ValueError as exc:
        raise DockerCollectionError(f"invalid Docker container port: {value!r}") from exc
    if not 0 < port <= 65535:
        raise DockerCollectionError(f"Docker container port out of range: {value!r}")
    protocol = protocol.strip().casefold()
    if not protocol:
        raise DockerCollectionError(f"Docker protocol missing from port key: {value!r}")
    return port, protocol


def parse_docker_inspect_published_ports(raw: str) -> tuple[DockerPublishedPort, ...]:
    """Parse running-container ``docker inspect`` output into publication facts."""

    raw = raw.strip()
    if not raw:
        return ()

    try:
        containers = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DockerCollectionError("docker inspect did not return valid JSON") from exc

    if isinstance(containers, Mapping):
        containers = [containers]
    if not isinstance(containers, list):
        raise DockerCollectionError("docker inspect root must be an object or array")

    results: list[DockerPublishedPort] = []
    for container in containers:
        if not isinstance(container, Mapping):
            raise DockerCollectionError("docker inspect container entry must be an object")

        container_id = container.get("Id")
        name = container.get("Name")
        config = container.get("Config")
        network = container.get("NetworkSettings")
        if not isinstance(container_id, str) or not container_id.strip():
            raise DockerCollectionError("docker inspect container is missing Id")
        if not isinstance(name, str) or not name.strip():
            raise DockerCollectionError("docker inspect container is missing Name")
        clean_name = name.lstrip("/") or name

        image: str | None = None
        if isinstance(config, Mapping):
            image_value = config.get("Image")
            if image_value is not None:
                if not isinstance(image_value, str):
                    raise DockerCollectionError("docker inspect Config.Image must be a string")
                image = image_value

        if not isinstance(network, Mapping):
            raise DockerCollectionError("docker inspect container is missing NetworkSettings")
        ports = network.get("Ports")
        if ports is None:
            continue
        if not isinstance(ports, Mapping):
            raise DockerCollectionError("docker inspect NetworkSettings.Ports must be an object")

        for port_key, bindings in ports.items():
            container_port, protocol = _parse_port_key(str(port_key))
            if bindings is None:
                continue
            if not isinstance(bindings, list):
                raise DockerCollectionError(
                    f"Docker bindings for {port_key!r} must be an array or null"
                )
            for binding in bindings:
                if not isinstance(binding, Mapping):
                    raise DockerCollectionError(
                        f"Docker binding for {port_key!r} must be an object"
                    )
                host_ip = binding.get("HostIp")
                host_port = binding.get("HostPort")
                if not isinstance(host_ip, str) or not host_ip.strip():
                    raise DockerCollectionError(
                        f"Docker binding for {port_key!r} is missing HostIp"
                    )
                try:
                    host_port_int = int(host_port)
                except (TypeError, ValueError) as exc:
                    raise DockerCollectionError(
                        f"Docker binding for {port_key!r} has invalid HostPort"
                    ) from exc

                results.append(
                    DockerPublishedPort(
                        container_id=container_id,
                        container_name=clean_name,
                        image=image,
                        protocol=protocol,
                        container_port=container_port,
                        host_address=host_ip,
                        host_port=host_port_int,
                    )
                )

    return tuple(
        sorted(
            results,
            key=lambda item: (
                item.container_name.casefold(),
                item.protocol,
                item.container_port,
                item.host_address,
                item.host_port,
                item.container_id,
            ),
        )
    )


def _run_docker(args: list[str], *, timeout_seconds: float = 15.0) -> str:
    try:
        completed = subprocess.run(
            ["docker", *args],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise DockerCollectionError("docker executable was not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise DockerCollectionError("docker command timed out") from exc

    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        detail = f": {stderr}" if stderr else ""
        raise DockerCollectionError(
            f"docker {' '.join(args)} failed with exit code {completed.returncode}{detail}"
        )
    return completed.stdout


def collect_docker_published_ports() -> tuple[DockerPublishedPort, ...]:
    """Collect host-port publications for currently running Docker containers."""

    ids_raw = _run_docker(["ps", "-q", "--no-trunc"])
    container_ids = tuple(
        line.strip()
        for line in ids_raw.splitlines()
        if line.strip()
    )
    if not container_ids:
        return ()

    inspect_raw = _run_docker(["inspect", *container_ids])
    return parse_docker_inspect_published_ports(inspect_raw)
