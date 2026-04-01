from django.urls import path

from . import views

urlpatterns = [
    path("dashboard/", views.DashboardView.as_view()),
    path("scans/", views.ScanListView.as_view()),
    path("scans/<str:scan_type>/trigger/", views.TriggerScanView.as_view()),
    path("scans/<str:scan_type>/latest/", views.LatestScanView.as_view()),
    path("scans/<str:scan_id>/", views.ScanDetailView.as_view()),
]
