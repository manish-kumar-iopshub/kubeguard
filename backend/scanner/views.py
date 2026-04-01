from rest_framework.response import Response
from rest_framework.views import APIView

from . import services

VALID_SCAN_TYPES = {"pods", "secrets", "deployments"}


class DashboardView(APIView):
    def get(self, request):
        return Response(services.get_dashboard())


class ScanListView(APIView):
    def get(self, request):
        return Response(services.list_scans())


class TriggerScanView(APIView):
    def post(self, request, scan_type):
        if scan_type not in VALID_SCAN_TYPES:
            return Response({"error": f"Invalid scan type: {scan_type}"}, status=400)
        scan_id = services.trigger_scan(scan_type, request.data or {})
        return Response({"scan_id": scan_id, "status": "running"}, status=202)


class ScanDetailView(APIView):
    def get(self, request, scan_id):
        result = services.get_scan(scan_id)
        if not result:
            return Response({"error": "Scan not found"}, status=404)
        return Response(result)


class LatestScanView(APIView):
    def get(self, request, scan_type):
        if scan_type not in VALID_SCAN_TYPES:
            return Response({"error": f"Invalid scan type: {scan_type}"}, status=400)
        result = services.get_latest_scan(scan_type)
        if not result:
            return Response({"error": "No completed scans found"}, status=404)
        return Response(result)


class ScannerSettingsView(APIView):
    def get(self, request):
        return Response(services.get_scanner_settings())

    def put(self, request):
        body = request.data or {}
        saved = services.save_scanner_settings(
            body.get("exclude_namespaces", []),
            body.get("skip_workloads", []),
        )
        return Response(saved)


class DeploymentWorkloadView(APIView):
    def get(self, request, namespace, deployment):
        detail = services.deployment_detail(namespace, deployment)
        if detail.get("error"):
            return Response(detail, status=404)
        return Response(detail)


class DeploymentIgnoreRuleView(APIView):
    def post(self, request, namespace, deployment):
        rule = (request.data or {}).get("rule")
        if not rule or not isinstance(rule, str):
            return Response({"error": "Missing or invalid 'rule'"}, status=400)
        result = services.ignore_deployment_rule(namespace, deployment, rule.strip())
        return Response(result)

    def delete(self, request, namespace, deployment):
        rule = request.query_params.get("rule")
        if not rule:
            return Response({"error": "Missing query param 'rule'"}, status=400)
        result = services.unignore_deployment_rule(namespace, deployment, rule.strip())
        return Response(result)
