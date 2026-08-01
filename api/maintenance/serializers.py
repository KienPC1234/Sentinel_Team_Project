from rest_framework import serializers

class CrashReportRequestSerializer(serializers.Serializer):
    device_info = serializers.CharField(required=True)
    stack_trace = serializers.CharField(required=True)
    timestamp = serializers.IntegerField(required=True)
    version = serializers.CharField(required=False, default='')
    os_version = serializers.CharField(required=False, default='')
    severity = serializers.CharField(required=False, default='ERROR')

class CrashReportResponseSerializer(serializers.Serializer):
    status = serializers.CharField()
    report_id = serializers.UUIDField()
