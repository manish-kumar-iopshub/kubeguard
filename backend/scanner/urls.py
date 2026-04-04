from django.urls import path

from . import views

urlpatterns = [
    path("dashboard/", views.DashboardView.as_view()),
    path("settings/scanner/", views.ScannerSettingsView.as_view()),
    path("settings/secret-scanner/", views.SecretScannerSettingsView.as_view()),
    path("settings/api-pt-scanner/", views.ApiPtScannerSettingsView.as_view()),
    path("settings/pod-alerts/", views.PodAlertSettingsView.as_view()),
    path("scans/", views.ScanListView.as_view()),
    path("scans/<str:scan_type>/trigger/", views.TriggerScanView.as_view()),
    path("scans/<str:scan_type>/latest/", views.LatestScanView.as_view()),
    path("scans/<str:scan_id>/", views.ScanDetailView.as_view()),
    path(
        "deployments/<str:namespace>/<str:deployment>/",
        views.DeploymentWorkloadView.as_view(),
    ),
    path(
        "deployments/<str:namespace>/<str:deployment>/ignore-rule/",
        views.DeploymentIgnoreRuleView.as_view(),
    ),
    path(
        "secrets/<str:namespace>/<str:kind>/<str:object_name>/ignore-issue/",
        views.SecretIssueIgnoreView.as_view(),
    ),
    path(
        "secrets/<str:namespace>/<str:kind>/<str:object_name>/ignore-resource/",
        views.SecretResourceIgnoreView.as_view(),
    ),
    path("secret-leakage/ignores/", views.SecretLeakIgnoresOverviewView.as_view()),
]
