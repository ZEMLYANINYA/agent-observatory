import unittest
from unittest.mock import patch

from agent_observatory.endpoint.docker_ports import (
    DockerCollectionError,
    collect_docker_published_ports,
    parse_docker_inspect_published_ports,
)
from agent_observatory.endpoint.service_exposure import BindScope


class DockerPublishedPortTests(unittest.TestCase):
    def test_parse_docker_inspect_preserves_each_host_binding(self) -> None:
        raw = r'''
        [
          {
            "Id": "container-123",
            "Name": "/ollama",
            "Config": {"Image": "ollama/ollama:latest"},
            "NetworkSettings": {
              "Ports": {
                "11434/tcp": [
                  {"HostIp": "0.0.0.0", "HostPort": "11434"},
                  {"HostIp": "::", "HostPort": "11434"}
                ],
                "9999/tcp": null
              }
            }
          }
        ]
        '''

        ports = parse_docker_inspect_published_ports(raw)

        self.assertEqual(len(ports), 2)
        self.assertEqual({item.container_name for item in ports}, {"ollama"})
        self.assertEqual({item.container_port for item in ports}, {11434})
        self.assertEqual({item.host_port for item in ports}, {11434})
        self.assertEqual({item.host_address for item in ports}, {"0.0.0.0", "::"})
        self.assertTrue(all(item.bind_scope is BindScope.WILDCARD for item in ports))

    def test_parse_docker_inspect_is_deterministic_across_container_order(self) -> None:
        first = r'''
        [
          {"Id":"b","Name":"/zeta","Config":{"Image":"z"},"NetworkSettings":{"Ports":{"9000/tcp":[{"HostIp":"127.0.0.1","HostPort":"9000"}]}}},
          {"Id":"a","Name":"/alpha","Config":{"Image":"a"},"NetworkSettings":{"Ports":{"8000/tcp":[{"HostIp":"0.0.0.0","HostPort":"8000"}]}}}
        ]
        '''
        second = r'''
        [
          {"Id":"a","Name":"/alpha","Config":{"Image":"a"},"NetworkSettings":{"Ports":{"8000/tcp":[{"HostIp":"0.0.0.0","HostPort":"8000"}]}}},
          {"Id":"b","Name":"/zeta","Config":{"Image":"z"},"NetworkSettings":{"Ports":{"9000/tcp":[{"HostIp":"127.0.0.1","HostPort":"9000"}]}}}
        ]
        '''

        self.assertEqual(
            parse_docker_inspect_published_ports(first),
            parse_docker_inspect_published_ports(second),
        )

    def test_parse_docker_inspect_rejects_invalid_json(self) -> None:
        with self.assertRaisesRegex(DockerCollectionError, "valid JSON"):
            parse_docker_inspect_published_ports("not-json")

    def test_parse_docker_inspect_rejects_missing_host_ip(self) -> None:
        raw = r'''
        [{"Id":"a","Name":"/alpha","Config":{"Image":"a"},"NetworkSettings":{"Ports":{"8000/tcp":[{"HostIp":"","HostPort":"8000"}]}}}]
        '''
        with self.assertRaisesRegex(DockerCollectionError, "missing HostIp"):
            parse_docker_inspect_published_ports(raw)

    def test_collect_returns_empty_without_running_containers(self) -> None:
        with patch(
            "agent_observatory.endpoint.docker_ports._run_docker",
            return_value="\n",
        ) as run_docker:
            result = collect_docker_published_ports()

        self.assertEqual(result, ())
        run_docker.assert_called_once_with(["ps", "-q", "--no-trunc"])

    def test_collect_inspects_exact_running_container_ids(self) -> None:
        inspect_json = r'''
        [{"Id":"abc","Name":"/redis","Config":{"Image":"redis:7"},"NetworkSettings":{"Ports":{"6379/tcp":[{"HostIp":"127.0.0.1","HostPort":"6379"}]}}}]
        '''
        with patch(
            "agent_observatory.endpoint.docker_ports._run_docker",
            side_effect=["abc\ndef\n", inspect_json],
        ) as run_docker:
            result = collect_docker_published_ports()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].container_name, "redis")
        self.assertEqual(result[0].bind_scope, BindScope.LOOPBACK)
        self.assertEqual(
            [call.args[0] for call in run_docker.call_args_list],
            [["ps", "-q", "--no-trunc"], ["inspect", "abc", "def"]],
        )


if __name__ == "__main__":
    unittest.main()
