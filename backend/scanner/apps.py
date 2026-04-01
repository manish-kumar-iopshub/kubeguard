import os
import sys

from django.apps import AppConfig


class ScannerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "scanner"

    def ready(self):
        if os.getenv("ENABLE_BACKGROUND_SCANNERS", "true").lower() in ("0", "false", "no"):
            return
        if len(sys.argv) > 1 and sys.argv[1] not in ("runserver",):
            return
        # Avoid duplicate scheduler threads under Django autoreload.
        if os.environ.get("RUN_MAIN") not in (None, "true"):
            return
        from . import services

        services.start_background_jobs()
