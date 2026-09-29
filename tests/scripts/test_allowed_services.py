"""The proxy allows a case's services by the Cloud Control namespaces of its types: every one of
those must name a real service id, or the proxy refuses the whole service (2026-09-24: Firehose
in EC cases 66 and 70, `AWS::KinesisFirehose` -> `kinesisfirehose`, which is no service)."""

from __future__ import annotations

import unittest

import botocore.session

from harness.extractor.aws.capabilities import CAPABILITY_REGISTRY
from scripts.run_case import _NAMESPACE_SERVICES


class AllowedServicesTests(unittest.TestCase):
    def test_every_adapter_namespace_maps_to_a_real_service(self) -> None:
        known = set(botocore.session.get_session().get_available_services())
        bad = {}
        for cap in CAPABILITY_REGISTRY.values():
            namespace = cap.cloudcontrol_type.split("::")[1].lower()
            services = _NAMESPACE_SERVICES.get(namespace, (namespace,))
            missing = [s for s in services if s not in known]
            if missing:
                bad[cap.cloudcontrol_type] = missing
        self.assertEqual(bad, {}, "add these namespaces to scripts/run_case.py _NAMESPACE_SERVICES")

    def test_firehose(self) -> None:
        self.assertEqual(_NAMESPACE_SERVICES["kinesisfirehose"], ("firehose",))


if __name__ == "__main__":
    unittest.main()
