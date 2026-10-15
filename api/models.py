from django.db import models

class Alert(models.Model):
    timestamp = models.DateTimeField()
    source_ip = models.GenericIPAddressField()
    dest_ip = models.GenericIPAddressField()
    tactic = models.CharField(max_length=255)
    severity = models.CharField(max_length=50)
    summary = models.TextField()
    remediation = models.JSONField()
    raw_log = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.severity} - {self.tactic} from {self.source_ip}"
