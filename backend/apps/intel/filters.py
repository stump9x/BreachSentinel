import django_filters
from django.db.models import Case, F, IntegerField, Value, When

from .models import CompromisedCredential, DataLeak, Indicator, Threat, ThreatActor


def annotate_wire_sort_priority(queryset):
    """Pin fresh high-priority rows; decay older Vietnam pins off the top.

    Vietnam stories stay in the feed indefinitely (see filter_wire_feed), but only
    the last WIRE_VIETNAM_PIN_DAYS keep full ``wire_priority`` for ordering.
    Older high-priority rows are capped at WIRE_STALE_PRIORITY_CAP.
    """
    from datetime import timedelta

    from django.conf import settings
    from django.utils import timezone

    pin_days = int(getattr(settings, "WIRE_VIETNAM_PIN_DAYS", 7) or 7)
    pin_hours = int(getattr(settings, "WIRE_PRIORITY_PIN_HOURS", 0) or 0)
    if pin_hours <= 0:
        pin_hours = max(1, pin_days) * 24
    stale_cap = max(0, int(getattr(settings, "WIRE_STALE_PRIORITY_CAP", 15) or 15))
    pin_cut = timezone.now() - timedelta(hours=max(1, pin_hours))
    return queryset.annotate(
        wire_sort_priority=Case(
            When(published_at__gte=pin_cut, then=F("wire_priority")),
            When(wire_priority__lte=stale_cap, then=F("wire_priority")),
            default=Value(stale_cap),
            output_field=IntegerField(),
        )
    )


class IndicatorFilter(django_filters.FilterSet):
    value = django_filters.CharFilter(field_name="value", lookup_expr="icontains")
    domain = django_filters.CharFilter(
        field_name="normalized_value", lookup_expr="icontains"
    )
    tag = django_filters.CharFilter(field_name="tags__slug")
    first_seen_after = django_filters.IsoDateTimeFilter(
        field_name="first_seen", lookup_expr="gte"
    )
    last_seen_before = django_filters.IsoDateTimeFilter(
        field_name="last_seen", lookup_expr="lte"
    )

    class Meta:
        model = Indicator
        fields = {
            "ioc_type": ["exact"],
            "confidence": ["exact"],
            "tlp": ["exact"],
            "source": ["exact", "icontains"],
            "is_active": ["exact"],
        }


class ThreatFilter(django_filters.FilterSet):
    title = django_filters.CharFilter(field_name="title", lookup_expr="icontains")
    cve = django_filters.CharFilter(method="filter_cve")
    tag = django_filters.CharFilter(field_name="tags__slug")
    published_after = django_filters.IsoDateTimeFilter(
        field_name="published_at", lookup_expr="gte"
    )
    created_after = django_filters.IsoDateTimeFilter(
        field_name="created_at", lookup_expr="gte"
    )
    # Dual window: Vietnam kept indefinitely; general Wire ≤ WIRE_MAX_AGE_DAYS.
    # Vietnam pin-to-top is handled by wire_sort_priority (last WIRE_VIETNAM_PIN_DAYS).
    wire_feed = django_filters.BooleanFilter(method="filter_wire_feed")

    class Meta:
        model = Threat
        fields = {
            "severity": ["exact"],
            "status": ["exact"],
            "source": ["exact"],
            "is_kev": ["exact"],
        }

    def filter_cve(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(cve_ids__contains=[value.upper()])

    def filter_wire_feed(self, queryset, name, value):
        if not value:
            return queryset
        from datetime import timedelta

        from django.conf import settings
        from django.db.models import Q
        from django.utils import timezone

        now = timezone.now()
        general_days = int(getattr(settings, "WIRE_MAX_AGE_DAYS", 7) or 7)
        vietnam_days = int(getattr(settings, "WIRE_VIETNAM_MAX_AGE_DAYS", 0) or 0)
        general_cut = now - timedelta(days=general_days)
        # 0 / negative = keep all Vietnam-tagged stories (no age cut).
        if vietnam_days > 0:
            vietnam_cut = now - timedelta(days=vietnam_days)
            vietnam_q = Q(tags__slug="vietnam", published_at__gte=vietnam_cut)
        else:
            vietnam_q = Q(tags__slug="vietnam")
        eligible = (
            queryset.filter(wire_relevant=True)
            .exclude(title_vi="")
            .filter(vietnam_q | Q(published_at__gte=general_cut))
            .distinct()
        )
        return eligible


class DataLeakFilter(django_filters.FilterSet):
    title = django_filters.CharFilter(field_name="title", lookup_expr="icontains")
    domain = django_filters.CharFilter(
        field_name="affected_domain", lookup_expr="icontains"
    )
    org = django_filters.CharFilter(
        field_name="affected_organization", lookup_expr="icontains"
    )
    discovered_after = django_filters.IsoDateTimeFilter(
        field_name="discovered_at", lookup_expr="gte"
    )

    class Meta:
        model = DataLeak
        fields = {
            "leak_type": ["exact"],
            "severity": ["exact"],
            "status": ["exact"],
            "source": ["exact"],
        }


class CompromisedCredentialFilter(django_filters.FilterSet):
    email = django_filters.CharFilter(field_name="email", lookup_expr="icontains")
    username = django_filters.CharFilter(field_name="username", lookup_expr="icontains")
    domain = django_filters.CharFilter(field_name="domain", lookup_expr="icontains")

    class Meta:
        model = CompromisedCredential
        fields = {
            "leak": ["exact"],
            "stealer_family": ["exact"],
            "country": ["exact", "icontains"],
        }


class ThreatActorFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(field_name="name", lookup_expr="icontains")

    class Meta:
        model = ThreatActor
        fields = {
            "is_active": ["exact"],
            "country": ["exact", "icontains"],
        }
