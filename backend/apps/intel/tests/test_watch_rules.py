from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

from apps.intel.models import AlertNotification, Threat, WatchRule
from apps.intel.watching import match_threat_against_rules


class WatchRuleMatchingTests(TestCase):
    def test_keyword_match_creates_notification(self):
        User = get_user_model()
        user = User.objects.create_user(username="soc", password="x")
        rule = WatchRule.objects.create(
            name="Ransom watch",
            keyword="lockbit",
            target=WatchRule.Target.THREATS,
            created_by=user,
        )
        threat = Threat.objects.create(
            title="LockBit hits finance org",
            summary="New campaign",
            severity=Threat.Severity.HIGH,
            source=Threat.Source.RANSOMWARE,
        )
        notes = match_threat_against_rules(threat)
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0].rule_id, rule.id)
        self.assertTrue(
            AlertNotification.objects.filter(threat=threat, rule=rule).exists()
        )


class WatchRuleAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.user = User.objects.create_user(username="soc2", password="test-pass-123")
        self.client.force_authenticate(user=self.user)

    def test_create_watch_rule(self):
        response = self.client.post(
            "/api/v1/watch-rules/",
            {
                "name": "Domain watch",
                "keyword": "acme.corp",
                "target": "all",
                "min_severity": "low",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["keyword"], "acme.corp")
