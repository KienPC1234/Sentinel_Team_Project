from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema
from .models import CrashReport, ErrorLog
from .serializers import CrashReportRequestSerializer, CrashReportResponseSerializer

class ReportCrashView(APIView):
    """
    Submit crash logs from the device.
    """
    @extend_schema(
        request=CrashReportRequestSerializer,
        responses={200: CrashReportResponseSerializer}
    )
    def post(self, request):
        serializer = CrashReportRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        
        # Create crash report
        crash_report = CrashReport.objects.create(
            device_info=data['device_info'],
            stack_trace=data['stack_trace'],
            timestamp=data['timestamp'],
            version=data.get('version', ''),
            os_version=data.get('os_version', ''),
            severity=data.get('severity', 'ERROR')
        )
        
        # Log to error logs
        ErrorLog.objects.create(
            error_type='CRASH_REPORT',
            error_message=f"{data['device_info']}: {data['stack_trace'][:200]}",
            context={
                'report_id': str(crash_report.report_id),
                'device_info': data['device_info'],
                'version': data.get('version', ''),
                'severity': data.get('severity', 'ERROR')
            }
        )
        
        return Response({
            'status': 'success',
            'report_id': str(crash_report.report_id)
        })
