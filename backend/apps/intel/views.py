from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.permissions import IsAdminUser, IsAuthenticated

from .filters import (
    CompromisedCredentialFilter,
    DataLeakFilter,
    IndicatorFilter,
    ThreatActorFilter,
    ThreatFilter,
)
from .models import (
    AlertNotification,
    CompromisedCredential,
    DataLeak,
    FeedSource,
    Indicator,
    Tag,
    Threat,
    ThreatActor,
    WatchRule,
)
from .serializers import (
    AlertNotificationSerializer,
    CompromisedCredentialSerializer,
    DataLeakSerializer,
    FeedSourceSerializer,
    IndicatorSerializer,
    TagSerializer,
    ThreatActorSerializer,
    ThreatSerializer,
    WatchRuleSerializer,
)


class TagViewSet(viewsets.ModelViewSet):
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    search_fields = ("name", "slug")
    filter_backends = (SearchFilter, OrderingFilter)
    ordering_fields = ("name", "created_at")
    ordering = ("name",)


class ThreatActorViewSet(viewsets.ModelViewSet):
    queryset = ThreatActor.objects.all()
    serializer_class = ThreatActorSerializer
    filterset_class = ThreatActorFilter
    search_fields = ("name", "description", "country")
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter)
    ordering_fields = ("name", "created_at", "updated_at")
    ordering = ("name",)


class IndicatorViewSet(viewsets.ModelViewSet):
    queryset = Indicator.objects.prefetch_related("tags", "threat_actors").all()
    serializer_class = IndicatorSerializer
    filterset_class = IndicatorFilter
    search_fields = ("value", "description", "source")
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter)
    ordering_fields = ("last_seen", "first_seen", "created_at", "confidence")
    ordering = ("-last_seen",)


class ThreatViewSet(viewsets.ModelViewSet):
    queryset = Threat.objects.prefetch_related(
        "tags", "indicators", "threat_actors"
    ).all()
    serializer_class = ThreatSerializer
    filterset_class = ThreatFilter
    search_fields = ("title", "summary", "source_url")
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter)
    ordering_fields = (
        "published_at",
        "wire_priority",
        "wire_sort_priority",
        "severity",
        "evidence_score",
        "cvss_score",
        "created_at",
        "id",
    )
    ordering = ("-wire_sort_priority", "-published_at", "-id")

    def get_queryset(self):
        from .filters import annotate_wire_sort_priority

        # Always annotate so OrderingFilter can use wire_sort_priority safely.
        return annotate_wire_sort_priority(super().get_queryset())


class DataLeakViewSet(viewsets.ModelViewSet):
    queryset = DataLeak.objects.prefetch_related(
        "tags", "related_indicators", "credentials"
    ).all()
    serializer_class = DataLeakSerializer
    filterset_class = DataLeakFilter
    search_fields = (
        "title",
        "description",
        "affected_organization",
        "affected_domain",
    )
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter)
    ordering_fields = ("discovered_at", "severity", "record_count", "created_at")
    ordering = ("-discovered_at",)


class CompromisedCredentialViewSet(viewsets.ModelViewSet):
    queryset = CompromisedCredential.objects.select_related("leak").all()
    serializer_class = CompromisedCredentialSerializer
    filterset_class = CompromisedCredentialFilter
    search_fields = ("email", "username", "domain", "url")
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter)
    ordering_fields = ("created_at", "infected_at", "domain")
    ordering = ("-created_at",)


class FeedSourceViewSet(viewsets.ModelViewSet):
    queryset = FeedSource.objects.all()
    serializer_class = FeedSourceSerializer
    search_fields = ("name", "url", "country", "notes")
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter)
    filterset_fields = ("is_active", "category", "confidence", "country_code")
    ordering_fields = ("confidence", "name", "last_fetched_at", "created_at")
    ordering = ("confidence", "name")

    def get_permissions(self):
        # Reads: any authenticated analyst. Mutations: staff only (SSRF surface).
        if self.action in {"list", "retrieve"}:
            return [IsAuthenticated()]
        return [IsAdminUser()]


class WatchRuleViewSet(viewsets.ModelViewSet):
    serializer_class = WatchRuleSerializer
    search_fields = ("name", "keyword")
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter)
    filterset_fields = ("is_active", "target")
    ordering = ("name",)

    def get_queryset(self):
        qs = WatchRule.objects.all()
        user = self.request.user
        if user and user.is_authenticated and not user.is_staff:
            return qs.filter(created_by=user)
        return qs


class AlertNotificationViewSet(viewsets.ModelViewSet):
    serializer_class = AlertNotificationSerializer
    http_method_names = ["get", "patch", "head", "options"]
    filter_backends = (DjangoFilterBackend, OrderingFilter)
    filterset_fields = ("is_read", "severity")
    ordering = ("-created_at",)

    def get_queryset(self):
        from django.db.models import Q

        qs = AlertNotification.objects.select_related("rule", "threat", "leak")
        user = self.request.user
        if user and user.is_authenticated and not user.is_staff:
            return qs.filter(Q(recipient=user) | Q(recipient__isnull=True))
        return qs.all()
