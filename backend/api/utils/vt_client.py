"""
Hybrid Threat Intelligence client: VirusTotal v3 API + on-premise fallback.

- Nếu có VT_API_KEY: truy vấn VirusTotal cloud (70+ engines), merge với
  LocalSandboxAnalyzer (ClamAV + heuristics + Docker sandbox).
- Nếu không có key / VT lỗi / rate-limit: fallback 100% local, giữ nguyên
  interface cũ để không vỡ code gọi (scan_utils, scan_views, tasks).

VirusTotal Public API v3 docs: https://developers.virustotal.com/reference/overview
Free quota: ~4 req/phut, 500 req/ngay, 32MB upload truc tiep.
"""

import base64
import hashlib
import logging
import os
import time
from typing import Any, Dict, Optional

import requests

from api.utils.sandbox_analyzer import LocalSandboxAnalyzer

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024  # 32 MB


def _get_setting(name: str, default: Any = None) -> Any:
    try:
        from django.conf import settings
        if getattr(settings, "configured", False):
            return getattr(settings, name, default)
    except Exception:
        pass
    return os.getenv(name, default)


def _vt_stats_to_risk(stats: Dict[str, Any]) -> int:
    """Map VT last_analysis_stats -> risk 0-100 (bao thu, de phan bien)."""
    try:
        mal = int(stats.get("malicious", 0) or 0)
        sus = int(stats.get("suspicious", 0) or 0)
    except (TypeError, ValueError):
        return 0
    if mal >= 10:
        return 95
    if mal >= 5:
        return 90
    if mal >= 1:
        return 85
    if sus >= 3:
        return 65
    if sus >= 1:
        return 45
    return 5


def _sha256_of_string(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _sha256_of_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _cache_get(key: str) -> Any:
    try:
        from django.core.cache import cache
        return cache.get(key)
    except Exception:
        return None


def _cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        from django.core.cache import cache
        cache.set(key, value, ttl)
    except Exception:
        pass


class VTClient:
    """
    Hybrid client giu dung interface cu:
      - scan_url(url) -> dict{harmless, malicious, suspicious, undetected, total, risk_score, ...}
      - scan_file(path, timeout=60) -> dict{...verdict, risk_score, engines, ...}

    Khi VT_API_KEY duoc cau hinh, ket qua co them:
      - 'virustotal': {available, stats, positives, total_engines, permalink, ...}
      - 'sources': ['local', 'virustotal'] (hoac ['local'] khi fallback)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        daemon_url: Optional[str] = None,
        docker_image: Optional[str] = None,
        timeout: Optional[int] = None,
        vt_timeout: Optional[int] = None,
    ):
        resolved_key = (
            api_key
            or _get_setting("VT_API_KEY", "")
            or os.getenv("VT_API_KEY", "")
            or ""
        )
        self.vt_api_key = str(resolved_key).strip().strip("'\"")
        # Cho phep tat VT rieng biet ke ca khi co key (phuc vu test / on-premise only).
        # Neu caller truyen api_key truc tiep -> uu tien bat (phuc vu test/unit).
        explicit_key = bool(api_key and str(api_key).strip())
        enabled_flag = _get_setting("VT_ENABLED", None)
        if explicit_key:
            self.vt_enabled = True
            if not self.vt_api_key:
                self.vt_enabled = False
        elif enabled_flag is None:
            env_flag = os.getenv("VT_ENABLED", "")
            self.vt_enabled = bool(self.vt_api_key) if not env_flag else env_flag.lower() not in ("0", "false", "no")
        else:
            if isinstance(enabled_flag, str):
                self.vt_enabled = enabled_flag.lower() not in ("0", "false", "no") and bool(self.vt_api_key)
            else:
                self.vt_enabled = bool(enabled_flag) and bool(self.vt_api_key)

        vt_timeout_raw = vt_timeout or _get_setting("VT_TIMEOUT", 0) or os.getenv("VT_TIMEOUT", "")
        try:
            self.vt_timeout = int(vt_timeout_raw) if vt_timeout_raw else 10
        except (TypeError, ValueError):
            self.vt_timeout = 10
        try:
            self.vt_cache_ttl = int(_get_setting("VT_CACHE_TIMEOUT", 0) or os.getenv("VT_CACHE_TIMEOUT", "") or 3600)
        except (TypeError, ValueError):
            self.vt_cache_ttl = 3600

        self.analyzer = LocalSandboxAnalyzer(
            daemon_url=daemon_url,
            docker_image=docker_image,
            timeout=timeout,
        )
        self._session = requests.Session()
        if self.vt_api_key:
            self._session.headers.update({"x-apikey": self.vt_api_key})

    # ------------------------------------------------------------------ VT core
    def _vt_get(self, path: str) -> Optional[Dict[str, Any]]:
        if not self.vt_enabled:
            return None
        try:
            resp = self._session.get(f"{VT_BASE_URL}{path}", timeout=self.vt_timeout)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (401, 403):
                logger.error("[VirusTotal] API key khong hop le (401/403). Fallback local.")
                self.vt_enabled = False  # tranh spam log moi request
                return None
            if resp.status_code == 429:
                logger.warning("[VirusTotal] Rate-limit 429. Fallback local + cache ngan.")
                return None
            if resp.status_code == 404:
                return {"_not_found": True}
            logger.warning(f"[VirusTotal] GET {path} -> {resp.status_code}: {resp.text[:200]}")
            return None
        except Exception as e:
            logger.warning(f"[VirusTotal] GET {path} loi: {e}")
            return None

    def _vt_post_url_submit(self, url: str) -> Optional[str]:
        """Submit URL de VT phan tich, tra ve analysis_id (hoac None)."""
        try:
            resp = self._session.post(
                f"{VT_BASE_URL}/urls",
                data={"url": url},
                timeout=self.vt_timeout,
            )
            if resp.status_code in (200, 201):
                data = resp.json().get("data", {})
                return data.get("id")
            if resp.status_code == 429:
                logger.warning("[VirusTotal] Submit URL bi rate-limit 429.")
                return None
            logger.warning(f"[VirusTotal] Submit URL -> {resp.status_code}: {resp.text[:200]}")
            return None
        except Exception as e:
            logger.warning(f"[VirusTotal] Submit URL loi: {e}")
            return None

    @staticmethod
    def _url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode().strip("=")

    def _vt_lookup_url(self, url: str) -> Optional[Dict[str, Any]]:
        """GET /urls/{id}; neu 404 thi submit roi doc lai 1 lan (nhanh, khong poll dai)."""
        cached = _cache_get(f"vt:url:{_sha256_of_string(url)}")
        if isinstance(cached, dict) and cached.get("stats"):
            return cached
        data = self._vt_get(f"/urls/{self._url_id(url)}")
        if not self.vt_enabled:
            return None  # key sai / bi disable giua chung -> khong dot quota submit
        if data and not data.get("_not_found"):
            parsed = self._parse_url_report(data)
            if parsed:
                _cache_set(f"vt:url:{_sha256_of_string(url)}", parsed, self.vt_cache_ttl)
            return parsed
        # Chua co report -> submit de lan sau co (tra ve None de khong block request dong bo)
        analysis_id = self._vt_post_url_submit(url)
        if analysis_id:
            logger.info(f"[VirusTotal] URL submitted, analysis={analysis_id}")
        return None

    @staticmethod
    def _parse_url_report(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            attrs = payload.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {}) or {}
            results = attrs.get("last_analysis_results", {}) or {}
            positives = [eng for eng, r in results.items() if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious")]
            return {
                "stats": {
                    "harmless": int(stats.get("harmless", 0) or 0),
                    "malicious": int(stats.get("malicious", 0) or 0),
                    "suspicious": int(stats.get("suspicious", 0) or 0),
                    "undetected": int(stats.get("undetected", 0) or 0),
                    "timeout": int(stats.get("timeout", 0) or 0),
                },
                "total_engines": len(results) or sum(int(v or 0) for v in stats.values()),
                "positives": positives[:20],
                "reputation": attrs.get("reputation"),
                "categories": attrs.get("categories", {}),
                "permalink": payload.get("data", {}).get("links", {}).get("self", ""),
                "last_analysis_date": attrs.get("last_analysis_date"),
            }
        except Exception as e:
            logger.warning(f"[VirusTotal] Parse URL report loi: {e}")
            return None

    def _vt_lookup_file_by_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        cached = _cache_get(f"vt:file:{sha256}")
        if isinstance(cached, dict) and cached.get("stats"):
            return cached
        data = self._vt_get(f"/files/{sha256}")
        if not data or data.get("_not_found"):
            return None
        parsed = self._parse_file_report(data)
        if parsed:
            _cache_set(f"vt:file:{sha256}", parsed, max(self.vt_cache_ttl, 86400))
        return parsed

    @staticmethod
    def _parse_file_report(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            attrs = payload.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {}) or {}
            results = attrs.get("last_analysis_results", {}) or {}
            positives = [
                {"engine": eng, "category": r.get("category"), "result": r.get("result")}
                for eng, r in results.items()
                if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious")
            ]
            names = attrs.get("names", []) or []
            return {
                "stats": {
                    "harmless": int(stats.get("harmless", 0) or 0),
                    "malicious": int(stats.get("malicious", 0) or 0),
                    "suspicious": int(stats.get("suspicious", 0) or 0),
                    "undetected": int(stats.get("undetected", 0) or 0),
                    "timeout": int(stats.get("timeout", 0) or 0),
                },
                "total_engines": len(results) or sum(int(v or 0) for v in stats.values()),
                "positives": positives[:20],
                "threat_names": sorted({str(p.get("result")) for p in positives if p.get("result")})[:10],
                "names": names[:5],
                "size": attrs.get("size"),
                "type_description": attrs.get("type_description"),
                "sha256": attrs.get("sha256"),
                "permalink": payload.get("data", {}).get("links", {}).get("self", ""),
                "last_analysis_date": attrs.get("last_analysis_date"),
            }
        except Exception as e:
            logger.warning(f"[VirusTotal] Parse file report loi: {e}")
            return None

    def _vt_upload_file(self, file_path: str, file_size: int) -> Optional[Dict[str, Any]]:
        """Upload file len VT (file nho truc tiep, file lon qua upload_url), poll ngan."""
        try:
            upload_url = f"{VT_BASE_URL}/files"
            if file_size > VT_DIRECT_UPLOAD_LIMIT:
                url_data = self._vt_get("/files/upload_url")
                upload_url = ((url_data or {}).get("data") or "") if url_data else ""
                if not upload_url:
                    logger.warning("[VirusTotal] Khong lay duoc upload_url cho file lon.")
                    return None
            with open(file_path, "rb") as f:
                resp = self._session.post(upload_url, files={"file": (os.path.basename(file_path), f)}, timeout=max(self.vt_timeout, 30))
            if resp.status_code not in (200, 201):
                logger.warning(f"[VirusTotal] Upload file -> {resp.status_code}: {resp.text[:200]}")
                return None
            analysis_id = resp.json().get("data", {}).get("id")
            if not analysis_id:
                return None
            return self._vt_poll_analysis(analysis_id, timeout_s=25)
        except Exception as e:
            logger.warning(f"[VirusTotal] Upload file loi: {e}")
            return None

    def _vt_poll_analysis(self, analysis_id: str, timeout_s: int = 25) -> Optional[Dict[str, Any]]:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            data = self._vt_get(f"/analyses/{analysis_id}")
            if not data or data.get("_not_found"):
                time.sleep(3)
                continue
            attrs = data.get("data", {}).get("attributes", {})
            status = attrs.get("status")
            if status == "completed":
                stats = attrs.get("stats", {}) or {}
                results = attrs.get("results", {}) or {}
                positives = [
                    {"engine": eng, "category": r.get("category"), "result": r.get("result")}
                    for eng, r in results.items()
                    if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious")
                ]
                return {
                    "stats": {
                        "harmless": int(stats.get("harmless", 0) or 0),
                        "malicious": int(stats.get("malicious", 0) or 0),
                        "suspicious": int(stats.get("suspicious", 0) or 0),
                        "undetected": int(stats.get("undetected", 0) or 0),
                        "timeout": int(stats.get("timeout", 0) or 0),
                    },
                    "total_engines": len(results) or sum(int(v or 0) for v in stats.values()),
                    "positives": positives[:20],
                    "threat_names": sorted({str(p.get("result")) for p in positives if p.get("result")})[:10],
                    "analysis_id": analysis_id,
                    "pending": False,
                }
            time.sleep(3)
        logger.info(f"[VirusTotal] Analysis {analysis_id} chua xong trong {timeout_s}s (pending).")
        return {"stats": {"harmless": 0, "malicious": 0, "suspicious": 0, "undetected": 0, "timeout": 0},
                "total_engines": 0, "positives": [], "analysis_id": analysis_id, "pending": True}

    # ------------------------------------------------------------- public API
    def scan_url(self, url: str) -> Dict[str, Any]:
        try:
            local = self.analyzer.scan_url(url)
        except Exception as e:
            logger.error(f"[Hybrid Threat Engine] URL local scan error for {url}: {e}")
            local = {"harmless": 1, "malicious": 0, "suspicious": 0, "undetected": 0, "total": 1, "risk_score": 0}

        if not self.vt_enabled:
            local.setdefault("sources", ["local"])
            local.setdefault("engine", local.get("engine", "Local-Heuristic-URL-Intelligence"))
            return local

        vt = self._vt_lookup_url(url)
        if not vt or not vt.get("stats"):
            local["virustotal"] = {"available": False, "reason": "no_report_or_rate_limited"}
            local.setdefault("sources", ["local"])
            return local

        stats = vt["stats"]
        vt_risk = _vt_stats_to_risk(stats)
        merged = dict(local)
        merged["malicious"] = max(int(local.get("malicious", 0) or 0), stats["malicious"])
        merged["suspicious"] = max(int(local.get("suspicious", 0) or 0), stats["suspicious"])
        merged["harmless"] = int(local.get("harmless", 0) or 0) if merged["malicious"] or merged["suspicious"] else max(int(local.get("harmless", 0) or 0), stats["harmless"])
        merged["total"] = max(int(local.get("total", 1) or 1), int(vt.get("total_engines", 0) or 0))
        merged["risk_score"] = max(int(local.get("risk_score", 0) or 0), vt_risk)
        merged["sources"] = ["local", "virustotal"]
        merged["engine"] = "Hybrid-VirusTotal-Local-Intel"
        merged["virustotal"] = {
            "available": True,
            "stats": stats,
            "total_engines": vt.get("total_engines", 0),
            "positives": vt.get("positives", []),
            "reputation": vt.get("reputation"),
            "permalink": vt.get("permalink", ""),
        }
        proofs = list(merged.get("forensic_proofs", []) or [])
        if stats["malicious"]:
            proofs.append(f"VirusTotal: {stats['malicious']}/{merged['total']} engines flag MALICIOUS ({', '.join(map(str, vt.get('positives', [])[:5]))})")
        elif stats["suspicious"]:
            proofs.append(f"VirusTotal: {stats['suspicious']} engines flag SUSPICIOUS")
        merged["forensic_proofs"] = proofs
        return merged

    def scan_file(self, file_path: str, timeout: int = 60) -> Optional[Dict[str, Any]]:
        try:
            local = self.analyzer.scan_file(file_path, timeout=timeout)
        except Exception as e:
            logger.error(f"[Hybrid Threat Engine] File local scan error for {file_path}: {e}")
            return None
        if local is None:
            return None

        if not self.vt_enabled:
            local.setdefault("sources", ["local"])
            local.setdefault("virustotal", {"available": False, "reason": "disabled_no_api_key"})
            return local

        sha256 = _sha256_of_file(file_path)
        vt = self._vt_lookup_file_by_hash(sha256) if sha256 else None
        if vt is None and os.path.exists(file_path):
            try:
                size = os.path.getsize(file_path)
                # Gioi han upload VT de tranh DoS quota: chi upload file <= 100MB (khop ScanFileView.MAX_SIZE)
                if size <= 100 * 1024 * 1024:
                    vt = self._vt_upload_file(file_path, size)
                    if vt and sha256 and not vt.get("pending") and vt.get("stats", {}).get("malicious", 0) + vt.get("stats", {}).get("suspicious", 0) >= 0:
                        _cache_set(f"vt:file:{sha256}", vt, max(self.vt_cache_ttl, 86400))
                else:
                    vt = {"stats": {"harmless": 0, "malicious": 0, "suspicious": 0, "undetected": 0, "timeout": 0},
                          "pending": False, "reason": "file_too_large_for_vt"}
            except Exception as e:
                logger.warning(f"[VirusTotal] File upload flow loi: {e}")
                vt = None

        if not vt or not vt.get("stats") or vt.get("pending"):
            local["virustotal"] = {"available": False,
                                   "reason": "pending" if (vt or {}).get("pending") else "no_report_or_rate_limited",
                                   "analysis_id": (vt or {}).get("analysis_id", "")}
            local.setdefault("sources", ["local"])
            return local

        stats = vt["stats"]
        vt_risk = _vt_stats_to_risk(stats)
        local_risk = int(local.get("risk_score", 0) or 0)
        merged = dict(local)
        merged["malicious"] = max(int(local.get("malicious", 0) or 0), (1 if stats["malicious"] else 0))
        merged["suspicious"] = max(int(local.get("suspicious", 0) or 0), (1 if stats["suspicious"] and not stats["malicious"] else 0))
        merged["total"] = max(int(local.get("total", 1) or 1), int(vt.get("total_engines", 0) or 0))
        merged["risk_score"] = min(100, max(local_risk, vt_risk))
        if stats["malicious"]:
            merged["verdict"] = "MALICIOUS"
            if not merged.get("threat_family") and vt.get("threat_names"):
                merged["threat_family"] = vt["threat_names"][0]
        elif stats["suspicious"] and merged.get("verdict") == "SAFE":
            merged["verdict"] = "SUSPICIOUS"

        proofs = list(merged.get("forensic_evidence", []) or [])
        if stats["malicious"]:
            threats = ", ".join(vt.get("threat_names", [])[:5])
            proofs.append({
                "category": "VirusTotal Cloud Intel (70+ engines)",
                "severity": "CRITICAL",
                "description": f"VirusTotal: {stats['malicious']}/{merged['total']} engines khang dinh ma doc{(' (' + threats + ')') if threats else ''}",
                "evidence": f"VT malicious={stats['malicious']}, permalink={vt.get('permalink', '')}",
            })
        elif stats["suspicious"]:
            proofs.append({
                "category": "VirusTotal Cloud Intel (70+ engines)",
                "severity": "MEDIUM",
                "description": f"VirusTotal: {stats['suspicious']} engines danh dau NGHI NGO",
                "evidence": f"VT suspicious={stats['suspicious']}",
            })
        merged["forensic_evidence"] = proofs
        engines = dict(merged.get("engines", {}) or {})
        engines["virustotal"] = {
            "available": True,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "total_engines": vt.get("total_engines", 0),
            "threat_names": vt.get("threat_names", []),
            "permalink": vt.get("permalink", ""),
        }
        merged["engines"] = engines
        merged["virustotal"] = {
            "available": True,
            "stats": stats,
            "total_engines": vt.get("total_engines", 0),
            "positives": vt.get("positives", []),
            "threat_names": vt.get("threat_names", []),
            "permalink": vt.get("permalink", ""),
        }
        merged["sources"] = ["local", "virustotal"]
        merged["engine"] = "Hybrid-VirusTotal-Sentinel-Sandbox"
        # Cap nhat giai thich tong hop de UI hien ca 2 nguon
        try:
            base_explain = merged.get("ai_explanation", "") or ""
            if stats["malicious"] or stats["suspicious"]:
                merged["ai_explanation"] = (
                    f"{base_explain}\n[VirusTotal cloud: {stats['malicious']} malicious / "
                    f"{stats['suspicious']} suspicious / {merged['total']} engines]"
                ).strip()
        except Exception:
            pass
        return merged

    def close(self):
        try:
            self._session.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
