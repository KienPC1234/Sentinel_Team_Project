"""ShieldCall VN – Trust / Guardrail / Source Reliability / Privacy / VN sources views.

Phục vụ các yêu cầu cải tiến của hội đồng:
- #1 Guardrail: công khai chính sách & ngưỡng bất định.
- #2 Dữ liệu nguồn Việt Nam: kênh chính thức + tổng đài ngân hàng.
- #3 Độ tin cậy nguồn & giới hạn công cụ: danh mục nguồn.
- #4 Bằng chứng cho nhận định: định dạng evidence dùng chung.
- #5 Bảo mật dữ liệu: công bố chính sách riêng tư + công cụ redaction.
"""
import logging

from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from api.utils import privacy
from api.utils import trust_guard as tg
from api.utils import vn_sources
from api.utils.s3_sync import storage_status

logger = logging.getLogger(__name__)


class SourceCatalogView(APIView):
    """GET /api/v1/trust/sources/ — danh mục nguồn + độ tin cậy + giới hạn."""
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            dataset = vn_sources.tinnhiem_dataset_stats()
        except Exception:
            dataset = {}
        return Response({
            "policy": tg.trust_policy()["principle"],
            "gray_zone": tg.trust_policy()["gray_zone"],
            "sources": tg.source_catalog(),
            "vn_dataset": dataset,
        })


class TrustPolicyView(APIView):
    """GET /api/v1/trust/policy/ — chính sách tin cậy & guardrail."""
    permission_classes = [AllowAny]

    def get(self, request):
        return Response(tg.trust_policy())


class VNOfficialChannelsView(APIView):
    """GET /api/v1/trust/channels/ — kênh chính thức & tổng đài ngân hàng VN."""
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({
            "channels": vn_sources.vn_channels(),
            "bank_hotlines": vn_sources.VN_BANK_HOTLINES,
            "references": vn_sources.vn_reference_sources(),
            "press": vn_sources.vn_press_sources(),
        })


class PrivacyNoticeView(APIView):
    """GET /api/v1/trust/privacy/ — chính sách xử lý dữ liệu (điểm #5)."""
    permission_classes = [AllowAny]

    def get(self, request):
        return Response(privacy.privacy_notice())


class RedactPreviewView(APIView):
    """POST /api/v1/trust/redact/ — thử nghiệm redaction PII (chỉ hiển thị, không lưu)."""
    permission_classes = [AllowAny]

    def post(self, request):
        text = request.data.get("text", "")
        if not isinstance(text, str):
            text = str(text)
        return Response({
            "original_length": len(text),
            "redacted": privacy.redact_pii(text),
            "enabled": privacy.pii_redaction_enabled(),
        })


class StorageStatusView(APIView):
    """GET /api/v1/trust/storage/ — trạng thái object storage (không lộ khoá bí mật)."""
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            return Response(storage_status())
        except Exception as exc:
            return Response({"using_s3": False, "error": str(exc)[:200]})
