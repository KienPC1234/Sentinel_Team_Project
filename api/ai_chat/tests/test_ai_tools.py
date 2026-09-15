import hashlib
from datetime import date
from unittest.mock import patch
from django.test import TestCase
from django.contrib.auth import get_user_model

from api.phone_security.models import PhoneNumber, PhoneReport, PhoneRiskLevel
from api.core.models import (
    Domain, BankAccount, Report, EntityLink, TrendDaily,
    ScamType, Severity, ReportStatus
)
from api.utils.ollama_client import (
    _assistant_scan_phone,
    _assistant_scan_url,
    _assistant_scan_bank_account,
    _assistant_query_threat_database,
    _assistant_lookup_company,
    _assistant_get_latest_threat_trends,
    TOOLS
)

User = get_user_model()


class AIAgentToolsTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='security_tester', password='testpassword123')

    def test_tools_schema_integrity(self):
        """Validate that all registered tools have standard schemas and required parameters."""
        tool_names = [t['function']['name'] for t in TOOLS]
        required_tools = [
            'scan_phone', 'scan_url', 'scan_bank_account', 'stealth_browse',
            'query_threat_database', 'lookup_company', 'get_latest_threat_trends',
            'web_search', 'web_fetch'
        ]
        for req in required_tools:
            self.assertIn(req, tool_names)

        for t in TOOLS:
            fn = t['function']
            self.assertTrue(fn.get('name'))
            self.assertTrue(fn.get('description'))
            params = fn.get('parameters', {})
            self.assertEqual(params.get('type'), 'object')

    @patch('api.utils.ollama_client.web_search_query', return_value=[])
    @patch('api.utils.ollama_client._tool_lookup_scamwave', return_value={'content': 'Cảnh báo lừa đảo'})
    def test_scan_phone_with_blacklist_and_fraud_graph(self, mock_sw, mock_ws):
        """Test scan_phone detects blacklisted numbers, normalization (+84), reports, and EntityLinks."""
        phone_obj = PhoneNumber.objects.create(
            phone_number='0987111222',
            risk_level=PhoneRiskLevel.RED,
            risk_label='Giả mạo công an',
            carrier='Viettel',
            line_type='Mobile',
            reports_count=3
        )
        PhoneReport.objects.create(
            phone_number=phone_obj,
            report_type='FRAUD',
            description='Đối tượng xưng là cán bộ điều tra yêu cầu chuyển tiền'
        )
        Report.objects.create(
            reporter=self.user,
            target_type='phone',
            target_value='0987111222',
            scammer_phone='0987111222',
            scam_type=ScamType.POLICE_IMPERSONATION,
            severity=Severity.HIGH,
            status=ReportStatus.APPROVED,
            description='Gọi điện lừa đảo tài khoản'
        )
        EntityLink.objects.create(
            from_type='phone',
            from_entity_id=phone_obj.id,
            to_type='account',
            to_entity_id=999,
            link_reason='shared_report',
            confidence=0.9
        )

        # Query with international format +84
        res = _assistant_scan_phone('+84 987 111 222')

        self.assertEqual(res['target_phone'], '0987111222')
        self.assertTrue(res['is_scam'])
        self.assertEqual(res['risk_level'], 'RED')
        self.assertTrue(res['internal_database']['found'])
        self.assertEqual(res['internal_database']['carrier'], 'Viettel')
        self.assertEqual(len(res['internal_database']['recent_complaints']), 1)
        self.assertGreaterEqual(len(res['sentinel_reports']), 1)
        self.assertEqual(len(res['fraud_network']), 1)
        self.assertEqual(res['fraud_network'][0]['linked_entity_type'], 'account')
        self.assertEqual(res['fraud_network'][0]['linked_entity_id'], 999)

    @patch('api.utils.ollama_client.web_search_query', return_value=[])
    @patch('api.utils.ollama_client._tool_lookup_scamwave', return_value=None)
    def test_scan_phone_clean_number(self, mock_sw, mock_ws):
        """Test scan_phone handles unlisted safe phone numbers correctly."""
        res = _assistant_scan_phone('0909999888')
        self.assertEqual(res['target_phone'], '0909999888')
        self.assertFalse(res['is_scam'])
        self.assertEqual(res['risk_level'], 'SAFE')
        self.assertFalse(res['internal_database']['found'])
        self.assertEqual(len(res['sentinel_reports']), 0)
        self.assertEqual(len(res['fraud_network']), 0)

    @patch('api.utils.ollama_client.web_search_query', return_value=[])
    @patch('api.utils.puppeteer_host_client.fetch_with_puppeteer_host', return_value={'ok': False})
    @patch('api.utils.ollama_client._tool_lookup_trustpilot', return_value={'source': 'trustpilot', 'content': 'No reports'})
    def test_scan_url_subdomain_and_apex_domain_matching(self, mock_tp, mock_pup, mock_ws):
        """Test scan_url catches apex domain when subdomain is tested."""
        dom = Domain.objects.create(
            domain_name='evil-phishing.com',
            risk_score=90,
            scam_type=ScamType.PHISHING,
            report_count=5
        )
        EntityLink.objects.create(
            from_type='domain',
            from_entity_id=dom.id,
            to_type='phone',
            to_entity_id=123,
            link_reason='shared_text',
            confidence=0.85
        )

        # Test with a malicious subdomain URL
        res = _assistant_scan_url('https://login.secure.evil-phishing.com/account/login')

        self.assertEqual(res['apex_domain'], 'evil-phishing.com')
        self.assertTrue(res['is_scam'])
        self.assertEqual(res['risk_score'], 90)
        self.assertTrue(res['internal_database']['found'])
        self.assertEqual(res['internal_database']['matched_domain'], 'evil-phishing.com')
        self.assertEqual(len(res['fraud_network']), 1)
        self.assertEqual(res['fraud_network'][0]['linked_entity_type'], 'phone')

    @patch('api.utils.ollama_client.web_search_query', return_value=[])
    @patch('api.utils.ollama_client._tool_lookup_scamwave', return_value=None)
    def test_scan_bank_account_exact_hash_and_matching(self, mock_sw, mock_ws):
        """Test scan_bank_account matches SHA256 hashed account and links reports."""
        account_num = '9876543210'
        acc_hash = hashlib.sha256(account_num.encode()).hexdigest()
        bank_obj = BankAccount.objects.create(
            bank_name='MB',
            account_number_hash=acc_hash,
            account_number_masked='***3210',
            risk_score=85,
            report_count=4,
            scam_type=ScamType.BANK_IMPERSONATION
        )
        EntityLink.objects.create(
            from_type='account',
            from_entity_id=bank_obj.id,
            to_type='phone',
            to_entity_id=555,
            link_reason='shared_report',
            confidence=0.95
        )
        Report.objects.create(
            reporter=self.user,
            target_type='account',
            target_value=account_num,
            scammer_bank_account=account_num,
            scammer_bank_name='MB',
            scam_type=ScamType.BANK_IMPERSONATION,
            severity=Severity.HIGH,
            status=ReportStatus.APPROVED,
            description='Yêu cầu đặt cọc mua hàng nhưng chặn liên lạc'
        )

        res = _assistant_scan_bank_account(account_num, bank_name='MB')

        self.assertEqual(res['account_number'], account_num)
        self.assertTrue(res['is_scam'])
        self.assertEqual(res['risk_score'], 85)
        self.assertTrue(res['internal_database']['found'])
        self.assertEqual(res['internal_database']['masked_account'], '***3210')
        self.assertGreaterEqual(len(res['sentinel_reports']), 1)
        self.assertEqual(len(res['fraud_network']), 1)
        self.assertEqual(res['fraud_network'][0]['linked_entity_type'], 'phone')

    def test_query_threat_database_multi_table_search(self):
        """Test query_threat_database queries across Domain, PhoneNumber, BankAccount, and Report."""
        PhoneNumber.objects.create(
            phone_number='0911223344',
            risk_level=PhoneRiskLevel.RED,
            risk_label='Lừa đảo tuyển dụng'
        )
        Domain.objects.create(
            domain_name='tuyendung-scam.com',
            risk_score=95,
            scam_type=ScamType.RECRUITMENT_SCAM
        )
        acc_num = '1122334455'
        BankAccount.objects.create(
            bank_name='Techcombank',
            account_number_hash=hashlib.sha256(acc_num.encode()).hexdigest(),
            account_number_masked='***4455',
            risk_score=90
        )
        Report.objects.create(
            reporter=self.user,
            target_type='message',
            target_value='Tuyển cộng tác viên',
            description='Tin nhắn giả mạo Shopee tuyển dụng'
        )

        res = _assistant_query_threat_database('tuyển dụng', target_type='all')

        self.assertGreaterEqual(res['matched_reports_count'], 1)
        self.assertGreaterEqual(len(res['reports']), 1)
        self.assertGreaterEqual(len(res['blacklist_matches']['phones']), 1)
        self.assertEqual(res['blacklist_matches']['phones'][0]['phone_number'], '0911223344')

    def test_get_latest_threat_trends(self):
        """Test get_latest_threat_trends queries TrendDaily and high-severity Reports."""
        TrendDaily.objects.create(
            date=date.today(),
            region='VN',
            scam_type=ScamType.RECRUITMENT_SCAM,
            count=15
        )
        Report.objects.create(
            reporter=self.user,
            target_type='phone',
            target_value='0933333333',
            scam_type=ScamType.POLICE_IMPERSONATION,
            severity=Severity.CRITICAL,
            description='Cuộc gọi video giả mạo người thân'
        )

        res = _assistant_get_latest_threat_trends(limit=5)

        self.assertGreaterEqual(res['count'], 2)
        self.assertGreaterEqual(len(res['trends']), 1)
        self.assertEqual(res['trends'][0]['scam_type'], ScamType.RECRUITMENT_SCAM)
        self.assertEqual(res['trends'][0]['cases_count'], 15)
        self.assertGreaterEqual(len(res['recent_high_severity_reports']), 1)
        self.assertEqual(res['recent_high_severity_reports'][0]['severity'], Severity.CRITICAL)

    @patch('api.utils.ollama_client.lookup_tratencongty')
    def test_lookup_company_schema_and_resilience(self, mock_lookup):
        """Test lookup_company returns required structured keys without throwing exceptions."""
        mock_lookup.return_value = {
            'source': 'tratencongty',
            'query_url': 'https://tratencongty.com/search/0101234567/',
            'title': 'TraTenCongTy lookup for 0101234567',
            'content': 'Công ty TNHH Thử Nghiệm MST 0101234567',
            'links': ['https://tratencongty.com/company/test/'],
        }
        res = _assistant_lookup_company('0101234567')
        self.assertIn('query', res)
        self.assertIn('found', res)
        self.assertTrue(res['found'])
        self.assertIn('summary', res)
        self.assertIn('content', res)
        self.assertIn('links', res)
        self.assertEqual(res['query'], '0101234567')
