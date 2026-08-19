from rest_framework import serializers

from apps.integrations.models import (
    AIBriefing,
    GitHubFinding,
    GitHubScan,
    IntegrationSyncLog,
)


class AIBriefingSerializer(serializers.ModelSerializer):
    class Meta:
        model = AIBriefing
        fields = (
            "id",
            "title",
            "content",
            "provider",
            "status",
            "window_hours",
            "threat_count",
            "indicator_count",
            "leak_count",
            "error_message",
            "created_by",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class IntegrationSyncLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntegrationSyncLog
        fields = (
            "id",
            "target",
            "direction",
            "status",
            "message",
            "records_processed",
            "details",
            "created_at",
        )
        read_only_fields = fields


class GenerateBriefingSerializer(serializers.Serializer):
    window_hours = serializers.IntegerField(min_value=1, max_value=168, default=24)
    async_mode = serializers.BooleanField(default=False)


class KeywordSummarySerializer(serializers.Serializer):
    keyword = serializers.CharField(min_length=2, max_length=128)
    window_hours = serializers.IntegerField(min_value=24, max_value=720, default=168)
    async_mode = serializers.BooleanField(default=False)


class ExtractEntitiesSerializer(serializers.Serializer):
    text = serializers.CharField(max_length=200_000)
    persist = serializers.BooleanField(default=False)


class MISPSyncSerializer(serializers.Serializer):
    direction = serializers.ChoiceField(choices=["export", "import", "both"])
    limit = serializers.IntegerField(min_value=1, max_value=200, default=50)
    async_mode = serializers.BooleanField(default=False)


class SearxSearchSerializer(serializers.Serializer):
    query = serializers.CharField(min_length=2, max_length=200)
    engines = serializers.CharField(required=False, allow_blank=True, max_length=256)
    limit = serializers.IntegerField(min_value=1, max_value=60, default=40)
    persist = serializers.BooleanField(default=False)
    exact = serializers.BooleanField(default=True)
    # Force Exa even when Searx/X/Reddit already have enough hits (ignored if EXA_OSINT_MODE=off).
    use_exa = serializers.BooleanField(default=False)


class SearxScanSerializer(serializers.Serializer):
    limit_per_keyword = serializers.IntegerField(min_value=1, max_value=40, default=15)
    async_mode = serializers.BooleanField(default=True)


class GitHubScanCreateSerializer(serializers.Serializer):
    keyword = serializers.CharField(min_length=2, max_length=256, trim_whitespace=True)

    def validate_keyword(self, value):
        if any(ord(char) < 32 for char in value):
            raise serializers.ValidationError("Control characters are not allowed.")
        return " ".join(value.split())


class GitHubScanBulkDeleteSerializer(serializers.Serializer):
    ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        allow_empty=False,
        max_length=100,
    )


class GitHubScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = GitHubScan
        fields = (
            "id",
            "keyword",
            "status",
            "max_results",
            "repository_count",
            "file_count",
            "alert_count",
            "critical_count",
            "non_text_count",
            "api_requests",
            "rate_limit_remaining",
            "coverage_limited",
            "duration_ms",
            "error_message",
            "started_at",
            "completed_at",
            "created_by",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class GitHubFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = GitHubFinding
        fields = (
            "id",
            "repository",
            "owner",
            "file_path",
            "extension",
            "html_url",
            "repository_url",
            "is_text_file",
            "keyword_matches",
            "match_lines",
            "match_snippets",
            "severity",
            "alert_types",
            "evidence",
            "score",
            "created_at",
        )
        read_only_fields = fields


class GitHubRepositorySummarySerializer(serializers.Serializer):
    repository = serializers.CharField()
    owner = serializers.CharField(allow_blank=True)
    repository_url = serializers.CharField(allow_blank=True)
    file_count = serializers.IntegerField()
    match_total = serializers.IntegerField()
    alert_count = serializers.IntegerField()
    non_text_count = serializers.IntegerField()
    text_count = serializers.IntegerField()


class ForumClaimItemSerializer(serializers.Serializer):
    title = serializers.CharField(min_length=2, max_length=512)
    link = serializers.URLField(max_length=2048, required=False, allow_blank=True)
    url = serializers.URLField(max_length=2048, required=False, allow_blank=True)
    published = serializers.CharField(required=False, allow_blank=True, max_length=64)
    feed = serializers.CharField(required=False, allow_blank=True, max_length=64)


class ForumClaimIngestSerializer(serializers.Serializer):
    items = ForumClaimItemSerializer(many=True)
    async_mode = serializers.BooleanField(default=False)
