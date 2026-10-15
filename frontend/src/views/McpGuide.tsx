'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api, ApiError } from '../lib/api';
import { useAuth } from '../components/AuthContext';
import { showToast } from '../lib/ui/feedback';
import { sanitizeHtml } from '../lib/chat/markdown';
import { SITE_URL } from '../lib/site-config';

/* Port 1-1 từ PKV/templates/MCP/mcp_guide.html (2703 dòng).
 * Toàn bộ markup/class/text/icon giữ nguyên; Alpine.js (x-data/x-show/x-for/
 * @click/x-model/x-init/@submit) chuyển thành React state/hooks/handler.
 * Các lời gọi API playground giữ nguyên endpoint so với bản gốc.
 */

/* ---------- Kiểu dữ liệu ---------- */

interface ApiKeyRow {
  id: number;
  name: string;
  prefix?: string;
  tier?: string;
  daily_quota?: number;
  requests_today?: number;
  is_active?: boolean;
}

type Platform =
  | 'claude_chat'
  | 'claude'
  | 'cursor'
  | 'windsurf'
  | 'claude_code'
  | 'cline'
  | 'chatgpt';

type RiskKey = 'CRITICAL' | 'WARNING' | 'LOW' | 'SAFE';

/* ---------- Helper đọc dữ liệu unknown ---------- */

function obj(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : {};
}
function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function str(v: unknown): string {
  if (v === null || v === undefined) return '';
  return typeof v === 'string' ? v : String(v);
}
function num(v: unknown): number {
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) ? n : 0;
}
function strArr(v: unknown): string[] {
  return arr(v).map((x) => str(x));
}

/* ---------- Dữ liệu tĩnh ---------- */

const PLATFORMS: Array<{ id: Platform; label: string; pulse?: boolean }> = [
  { id: 'claude_chat', label: 'Claude Chat (Web / Mobile)', pulse: true },
  { id: 'claude', label: 'Claude Desktop' },
  { id: 'cursor', label: 'Cursor IDE' },
  { id: 'windsurf', label: 'Windsurf' },
  { id: 'claude_code', label: 'Claude Code CLI' },
  { id: 'cline', label: 'Cline / Roo Code' },
  { id: 'chatgpt', label: 'ChatGPT Actions' },
];

interface ToolDef {
  tool: string;
  icon: string;
  desc: string;
  badge: string;
}

const PLAYGROUND_TOOLS: ToolDef[] = [
  { tool: 'check_phone', icon: 'bi-telephone-fill', desc: 'Quét SĐT, VoIP, nhà mạng', badge: 'bg-white/10 text-brand-300/80' },
  { tool: 'check_bank_account', icon: 'bi-credit-card-2-front-fill', desc: 'Đối soát STK lừa đảo', badge: 'bg-white/10 text-brand-300/80' },
  { tool: 'check_url_or_domain', icon: 'bi-globe2', desc: 'Phishing & chứng chỉ SSL', badge: 'bg-white/10 text-brand-300/80' },
  { tool: 'analyze_message', icon: 'bi-chat-left-dots-fill', desc: 'Bẫy tâm lý, SMS đòi OTP', badge: 'bg-white/10 text-brand-300/80' },
  { tool: 'check_email_sender', icon: 'bi-envelope-at-fill', desc: 'SPF, DKIM, DMARC mail', badge: 'bg-white/10 text-brand-300/80' },
  { tool: 'scan_full_incident', icon: 'bi-shield-check', desc: 'Quét tổng hợp đa nguồn', badge: 'bg-brand-300/80' },
  { tool: 'lookup_scam_db', icon: 'bi-search', desc: 'Tra cứu kho hồ sơ đen', badge: 'bg-safe-500/20 text-safe-300' },
  { tool: 'get_scam_radar_trends', icon: 'bi-radar', desc: 'Radar xu hướng thực', badge: 'bg-safe-500/20 text-safe-300' },
  { tool: 'get_supported_banks', icon: 'bi-bank', desc: '65+ ngân hàng VietQR', badge: 'bg-safe-500/20 text-safe-300' },
  { tool: 'report_scam', icon: 'bi-flag-fill', desc: 'Gửi báo cáo lừa đảo', badge: 'bg-white/10 text-brand-300/80' },
];

const PROMPT_SENTRY = `You are ShieldCall Sentry, an automated cybersecurity assistant and scam detection copilot integrated with the ShieldCall VN platform.

OPERATIONAL DIRECTIVES:
1. Multi-entity incidents: If an incident involves multiple indicators (e.g., phone number, URL/domain, and bank account), immediately call 'scan_full_incident' to run a unified composite triage.
2. Single-entity inquiries: Query the corresponding ShieldCall MCP tool (check_phone, check_bank_account, check_url_or_domain, analyze_message, check_email_sender, get_supported_banks) before providing analysis.
3. Standardized Risk Scoring Scale:
   - 0-19: SAFE (Low likelihood of malicious intent)
   - 20-49: LOW (Exercise caution, unverified identifiers)
   - 50-79: MEDIUM (Suspicious patterns detected, potential fraud)
   - 80-100: CRITICAL (Confirmed malicious activity, verified fraud reports)
4. Tactical guidance: Explicitly instruct users never to transfer funds, install unverified APK packages, or provide OTP credentials to untrusted parties.`;

const PROMPT_EMERGENCY = `You are a specialized Incident Response Agent integrated with the ShieldCall VN security platform.

IMMEDIATE INCIDENT RESPONSE PROTOCOL:
1. CONTAINMENT: Instruct the victim to immediately contact their bank's fraud desk to freeze impacted accounts and payment cards. If malicious software was installed, immediately disconnect the device from cellular and Wi-Fi networks.
2. IDENTIFIER TRIAGE: Invoke 'scan_full_incident', 'check_bank_account', or 'check_phone' to cross-reference fraud records against the threat intelligence database.
3. EVIDENCE PRESERVATION: Instruct the user to preserve transaction receipts, FT codes, chat transcripts, and caller IDs without alerting the adversary.
4. INCIDENT ESCALATION: Guide the user to file official reports with law enforcement authorities and invoke 'report_scam' to record new threat indicators.`;

const PROMPT_INVESTIGATOR = `You are a Technical Fraud Forensic Analyst integrated with the ShieldCall VN threat intelligence platform.

TECHNICAL INVESTIGATION PROTOCOL:
- Evaluate domain WHOIS, age, and Levenshtein distance against known legitimate services to detect lookalike phishing domains.
- Validate email authentication headers including SPF, DKIM, and DMARC alignment via 'check_email_sender'.
- Analyze telecommunication carrier prefixes to identify VoIP or disposable virtual numbers via 'check_phone'.
- Verify banking BIN codes and fraud records via 'get_supported_banks' and 'check_bank_account'.
- Correlate indicators using 'scan_full_incident' to output a structured technical risk analysis report.`;

interface PromptCard {
  id: string;
  badge: string;
  badgeCls: string;
  icon: string;
  title: string;
  desc: string;
  text: string;
  btnCls: string;
  btnText: string;
  cardCls: string;
}

const PROMPT_CARDS: PromptCard[] = [
  {
    id: 'p1-btn',
    badge: 'Phổ biến nhất • Khuyên dùng',
    badgeCls: 'bg-brand-400/15 text-brand-300',
    icon: 'bi-shield-lock-fill text-brand-400 text-lg',
    title: '1. Vệ Binh Không Gian Mạng (ShieldCall Sentry)',
    desc: 'Thường trực ngầm, tự động gọi công cụ tra cứu ngay khi người dùng vô tình nhắc đến bất kỳ số điện thoại, tài khoản ngân hàng hoặc link website nào.',
    text: PROMPT_SENTRY,
    btnCls: 'bg-brand-400 text-black hover:bg-brand-300 shadow-lg shadow-brand-400/20',
    btnText: 'Sao chép Prompt Sentry',
    cardCls: 'border-brand-500/30 bg-brand-500/[0.02]',
  },
  {
    id: 'p2-btn',
    badge: 'Ứng cứu khẩn cấp',
    badgeCls: 'bg-danger-400/15 text-danger-400',
    icon: 'bi-exclamation-octagon-fill text-danger-400 text-lg',
    title: '2. Phản Ứng Sự Cố Khẩn Cấp (Emergency Responder)',
    desc: 'Chuyên xử lý khi người dùng vừa chuyển tiền cho kẻ gian, lỡ bấm link lạ tải file .APK hoặc bị lộ mã OTP. Hướng dẫn quy trình 4 bước chặn đứng thiệt hại.',
    text: PROMPT_EMERGENCY,
    btnCls: 'bg-danger-500 text-white hover:bg-danger-400 shadow-lg shadow-danger-500/20',
    btnText: 'Sao chép Prompt Ứng Cứu',
    cardCls: 'border-danger-500/30 bg-danger-500/[0.02]',
  },
  {
    id: 'p3-btn',
    badge: 'Dành cho Kỹ thuật viên & OSINT',
    badgeCls: 'bg-brand2-400/15 text-brand2-300',
    icon: 'bi-search text-brand2-400 text-lg',
    title: '3. Giám Định Gian Lận Số (Forensic Investigator)',
    desc: 'Phân tích sâu kỹ thuật: WHOIS domain, khoảng cách Levenshtein nhận diện tên miền nhái, phân tích nhà mạng và cước số ảo VoIP.',
    text: PROMPT_INVESTIGATOR,
    btnCls: 'bg-brand2-500 text-white hover:bg-brand2-400 shadow-lg shadow-brand2-500/20',
    btnText: 'Sao chép Prompt Giám Định',
    cardCls: 'border-brand2-500/30 bg-brand2-500/[0.02]',
  },
];

interface ToolRow {
  name: string;
  params: string[];
  use: string;
  returns: string;
}

const TOOLS_TABLE: ToolRow[] = [
  { name: 'check_phone', params: ['phone_number: str'], use: 'Quét độ rủi ro SĐT, kiểm tra blacklist, số ảo/VoIP, lịch sử khiếu nại', returns: 'risk_score, risk_level, carrier, line_type, suggested_action' },
  { name: 'check_bank_account', params: ['bank_name: str', 'account_number: str'], use: 'Tra cứu số tài khoản ngân hàng trong danh sách đen lừa đảo cộng đồng', returns: 'risk_score, risk_level, report_count, details' },
  { name: 'check_url_or_domain', params: ['url: str'], use: 'Phát hiện tên miền giả mạo (lookalike), SSL, DNS, trang web phishing', returns: 'risk_score, risk_level, is_lookalike, flags' },
  { name: 'analyze_message', params: ['message_content: str'], use: 'Phân tích kịch bản SMS lừa đảo mạo danh công an, ngân hàng, nạp tiền OTP', returns: 'risk_score, risk_level, scam_type, analysis' },
  { name: 'lookup_scam_db', params: ['query: str', "entity_type: str = 'all'"], use: 'Tìm kiếm đối tượng hoặc từ khóa bất kỳ trong cơ sở dữ liệu ShieldCall', returns: 'matches, reports, entities' },
  { name: 'check_email_sender', params: ['sender_email: str', "email_content: str = ''", "email_subject: str = ''"], use: 'Kiểm tra SPF, DKIM, DMARC tên miền gửi thư và phát hiện nội dung email lừa đảo', returns: 'risk_score, risk_level, security_checks, extracted_info' },
  { name: 'get_supported_banks', params: [], use: 'Lấy danh mục ngân hàng chuẩn Việt Nam kèm mã BIN để thẩm định tài khoản thụ hưởng', returns: 'name, code, bin, shortName' },
  { name: 'scan_full_incident', params: ["message_content: str = ''", "phone_number: str = ''", "bank_name: str = ''", "account_number: str = ''", "url: str = ''", "sender_email: str = ''"], use: 'Giám định tổng thể đa thực thể vụ việc nghi vấn lừa đảo trong một lần gọi duy nhất', returns: 'overall_risk_score, overall_risk_level, entities_scanned, detected_threats, recommended_actions' },
  { name: 'get_scam_radar_trends', params: [], use: 'Lấy dữ liệu radar thủ đoạn lừa đảo và số liệu thống kê thời gian thực', returns: 'top_scam_types, daily_trend, total_reports' },
  { name: 'report_scam', params: ['target_type: str', 'target_value: str', 'scam_type: str', 'description: str'], use: 'Cho phép AI hỗ trợ người dùng gửi báo cáo lừa đảo về ban quản trị', returns: 'status, report_id' },
];

const BANK_SUGGESTIONS: Array<{ value: string; label: string }> = [
  { value: 'MB', label: 'MBBank' },
  { value: 'VCB', label: 'Vietcombank' },
  { value: 'TCB', label: 'Techcombank' },
  { value: 'VPB', label: 'VPBank' },
  { value: 'ACB', label: 'ACB' },
  { value: 'BIDV', label: 'BIDV' },
  { value: 'VBA', label: 'Agribank' },
  { value: 'TPB', label: 'TPBank' },
];

const RISK_UI: Record<RiskKey, { banner: string; icon: string; text: string; bar: string }> = {
  CRITICAL: { banner: 'bg-danger-950/30 border-danger-500/40 text-danger-300', icon: 'bi-shield-fill-x text-danger-400', text: 'text-danger-400', bar: 'bg-danger-500' },
  WARNING: { banner: 'bg-warn-950/30 border-warn-500/40 text-warn-300', icon: 'bi-shield-fill-exclamation text-warn-400', text: 'text-warn-400', bar: 'bg-warn-400' },
  LOW: { banner: 'bg-brand-950/30 border-brand-500/40 text-brand-300', icon: 'bi-shield-fill-check text-brand-400', text: 'text-brand-400', bar: 'bg-brand-400' },
  SAFE: { banner: 'bg-safe-950/30 border-safe-500/40 text-safe-300', icon: 'bi-shield-fill-check text-safe-400', text: 'text-safe-400', bar: 'bg-safe-400' },
};

/* Khối "Chuẩn bị: Tải script độc lập" dùng lại ở 5 tab nền tảng. */
function DownloadPrereq({ label, zeroDepText }: { label: string; zeroDepText: string }) {
  const origin = typeof window !== 'undefined' ? window.location.origin : SITE_URL;
  const curlCmd = `curl -sSL ${origin}/mcp/download/ -o shieldcall_mcp.py`;
  return (
    <div className="p-4 rounded-2xl bg-white/[0.03] border border-brand-400/20 space-y-3">
      <p className="text-xs font-black text-white uppercase tracking-wider flex items-center gap-2">
        <span className="w-5 h-5 rounded-full bg-brand-400/20 text-brand-300 flex items-center justify-center font-bold text-[10px] shrink-0">1</span>
        Chuẩn bị: Tải script độc lập (Zero-Dependency)
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
        <div className="space-y-1.5">
          <p className="text-[10px] font-bold text-white/60 uppercase tracking-wider">{label}</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 p-2.5 bg-black/60 border border-white/10 rounded-xl text-brand-300 select-all text-[11px]">{curlCmd}</code>
            <a href="/mcp/download/" download="shieldcall_mcp.py" className="shrink-0 px-3 py-2 rounded-xl text-[10px] font-black bg-brand-400 text-black hover:bg-brand-300 uppercase tracking-wider flex items-center gap-1 whitespace-nowrap">
              <i className="bi bi-download"></i> Tải ngay
            </a>
          </div>
        </div>
        <div className="space-y-1.5">
          <p className="text-[10px] font-bold text-safe-400 uppercase tracking-wider flex items-center gap-1">
            <i className="bi bi-shield-check"></i> 100% Zero-Dependency:
          </p>
          <div className="p-2.5 bg-safe-500/10 border border-safe-500/20 rounded-xl text-safe-300 text-[11px]">
            {zeroDepText}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ---------- Component ---------- */

export default function McpGuide() {
  const { user } = useAuth();

  const [origin, setOrigin] = useState('');
  const [userKeys, setUserKeys] = useState<ApiKeyRow[]>([]);
  const [selectedKey, setSelectedKey] = useState('');
  const [activePlatform, setActivePlatform] = useState<Platform>('claude_chat');
  const [pythonPath, setPythonPath] = useState('python');
  const [scriptPath, setScriptPath] = useState('shieldcall_mcp.py');
  const [copiedId, setCopiedId] = useState('');

  const [playgroundTool, setPlaygroundTool] = useState('check_phone');
  const [playgroundTab, setPlaygroundTab] = useState<'visual' | 'json'>('visual');
  const [showKeyInput, setShowKeyInput] = useState(false);
  const [playgroundCustomKey, setPlaygroundCustomKey] = useState('');
  const [playgroundPhone, setPlaygroundPhone] = useState('0912345678');
  const [playgroundBank, setPlaygroundBank] = useState('MB');
  const [playgroundAccount, setPlaygroundAccount] = useState('0987654321');
  const [playgroundUrl, setPlaygroundUrl] = useState('http://dichvucong-vn.top');
  const [playgroundMessage, setPlaygroundMessage] = useState('Ngân hàng MB thông báo tài khoản của quý khách bị phong tỏa do nghi ngờ gian lận. Vui lòng gửi mã OTP xác minh ngay hoặc truy cập http://dichvucong-vn.top để mở khóa.');
  const [playgroundEmail, setPlaygroundEmail] = useState('fraud@phishing-fake-bank.top');
  const [playgroundQuery, setPlaygroundQuery] = useState('0912345678');
  const [playgroundEntityType, setPlaygroundEntityType] = useState('all');
  const [playgroundReportTargetType, setPlaygroundReportTargetType] = useState('phone');
  const [playgroundReportTargetValue, setPlaygroundReportTargetValue] = useState('0988776655');
  const [playgroundReportScamType, setPlaygroundReportScamType] = useState('phishing');
  const [playgroundReportDescription, setPlaygroundReportDescription] = useState('Giả mạo nhân viên ngân hàng gọi điện yêu cầu cung cấp mã OTP để nâng cấp hạn mức tín dụng.');
  const [playgroundLoading, setPlaygroundLoading] = useState(false);
  const [playgroundResult, setPlaygroundResult] = useState<unknown>(null);
  const [playgroundLatency, setPlaygroundLatency] = useState(0);
  const [playgroundHttpStatus, setPlaygroundHttpStatus] = useState<number | null>(null);
  const [playgroundError, setPlaygroundError] = useState<string | null>(null);
  const [bankSearchFilter, setBankSearchFilter] = useState('');

  useEffect(() => {
    setOrigin(window.location.origin);
  }, []);

  useEffect(() => {
    if (!user) return;
    let alive = true;
    api
      .get<{ api_keys?: ApiKeyRow[] } | ApiKeyRow[]>('/user/api-keys/')
      .then((d) => {
        if (!alive) return;
        const list = Array.isArray(d) ? d : d.api_keys || [];
        setUserKeys(list.filter((k) => k.is_active));
      })
      .catch(() => {
        if (alive) setUserKeys([]);
      });
    return () => {
      alive = false;
    };
  }, [user]);

  /* Khóa API chỉ dùng khi đã đăng nhập (giống {% if user.is_authenticated %} + user_api_keys). */
  const activeKeys = user ? userKeys : [];
  const effectiveSelectedKey =
    selectedKey || (activeKeys.length > 0 && activeKeys[0]?.prefix ? `${activeKeys[0].prefix}_secret_key_here` : 'sc_live_your_api_key_here');

  const siteUrl = origin;
  const apiUrl = `${origin}/api/v1`;

  const getCurrentApiKey = (): string => {
    if (!effectiveSelectedKey || effectiveSelectedKey.includes('undefined')) {
      if (activeKeys.length > 0 && activeKeys[0]?.prefix) return `${activeKeys[0].prefix}_secret_key_here`;
      return 'sc_live_your_api_key_here';
    }
    return effectiveSelectedKey;
  };

  const getClaudeChatConnectorUrl = (): string => {
    const base = (siteUrl || origin).replace(/\/+$/, '');
    return `${base}/api/v1/mcp/sse/?api_key=${getCurrentApiKey()}`;
  };

  /* ---------- Config snippets ---------- */

  const getClaudeConfig = (): string =>
    JSON.stringify(
      {
        mcpServers: {
          shieldcall: {
            command: pythonPath || 'python',
            args: [scriptPath],
            env: {
              SHIELDCALL_API_KEY: getCurrentApiKey(),
              SHIELDCALL_API_URL: apiUrl,
            },
          },
        },
      },
      null,
      2,
    );

  const getCursorConfig = (): string => getClaudeConfig();

  const getWindsurfConfig = (): string => getClaudeConfig();

  const getClaudeCodeCommand = (): string =>
    `claude mcp add shieldcall ${pythonPath || 'python'} ${scriptPath} -e SHIELDCALL_API_KEY=${getCurrentApiKey()} -e SHIELDCALL_API_URL=${apiUrl}`;

  const getClineConfig = (): string =>
    JSON.stringify(
      {
        mcpServers: {
          shieldcall: {
            command: pythonPath || 'python',
            args: [scriptPath],
            env: {
              SHIELDCALL_API_KEY: getCurrentApiKey(),
              SHIELDCALL_API_URL: apiUrl,
            },
            disabled: false,
            autoApprove: [
              'check_phone',
              'check_bank_account',
              'check_url_or_domain',
              'analyze_message',
              'lookup_scam_db',
              'get_scam_radar_trends',
            ],
          },
        },
      },
      null,
      2,
    );

  const getChatGPTSchema = (): string => {
    const schema = {
      openapi: '3.1.0',
      info: {
        title: 'ShieldCall VN Scam Detection API',
        version: '1.0.0',
        description: 'API thẩm định lừa đảo trực tuyến tại Việt Nam.',
      },
      servers: [{ url: apiUrl }],
      paths: {
        '/scan/phone/': {
          post: {
            operationId: 'check_phone',
            summary: 'Quét số điện thoại',
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: { phone: { type: 'string' } },
                    required: ['phone'],
                  },
                },
              },
            },
            responses: { '200': { description: 'Kết quả rủi ro' } },
          },
        },
        '/scan/account/': {
          post: {
            operationId: 'check_bank_account',
            summary: 'Kiểm tra số tài khoản ngân hàng',
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      bank: { type: 'string' },
                      account: { type: 'string' },
                    },
                    required: ['bank', 'account'],
                  },
                },
              },
            },
            responses: { '200': { description: 'Kết quả tài khoản' } },
          },
        },
        '/scan/domain/': {
          post: {
            operationId: 'check_domain',
            summary: 'Kiểm tra tên miền hoặc URL',
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: { url: { type: 'string' } },
                    required: ['url'],
                  },
                },
              },
            },
            responses: { '200': { description: 'Kết quả tên miền' } },
          },
        },
        '/scan/message/': {
          post: {
            operationId: 'analyze_message',
            summary: 'Phân tích tin nhắn SMS lừa đảo',
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      message: { type: 'string' },
                      sync: { type: 'boolean', default: true },
                    },
                    required: ['message'],
                  },
                },
              },
            },
            responses: { '200': { description: 'Kết quả phân tích tin nhắn' } },
          },
        },
        '/scan/email/': {
          post: {
            operationId: 'check_email_sender',
            summary: 'Kiểm tra email người gửi và nội dung thư',
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      sender_email: { type: 'string' },
                      email_content: { type: 'string' },
                      sync: { type: 'boolean', default: true },
                    },
                    required: ['sender_email'],
                  },
                },
              },
            },
            responses: { '200': { description: 'Kết quả kiểm tra email' } },
          },
        },
        '/scan/banks/': {
          get: {
            operationId: 'get_supported_banks',
            summary: 'Danh mục ngân hàng Việt Nam',
            responses: { '200': { description: 'Danh sách ngân hàng' } },
          },
        },
        '/scan/lookup/': {
          get: {
            operationId: 'lookup_scam_db',
            summary: 'Tra cứu cơ sở dữ liệu lừa đảo',
            parameters: [
              { name: 'q', in: 'query', required: true, schema: { type: 'string' } },
              { name: 'type', in: 'query', required: false, schema: { type: 'string', default: 'all' } },
            ],
            responses: { '200': { description: 'Kết quả tra cứu' } },
          },
        },
      },
    };
    return JSON.stringify(schema, null, 2);
  };

  /* ---------- Copy to clipboard ---------- */

  const copyText = (text: string, btnId: string) => {
    if (typeof navigator === 'undefined' || !navigator.clipboard) {
      showToast('Không thể sao chép.', 'error');
      return;
    }
    void navigator.clipboard
      .writeText(text)
      .then(() => {
        setCopiedId(btnId);
        setTimeout(() => setCopiedId((cur) => (cur === btnId ? '' : cur)), 2000);
      })
      .catch(() => showToast('Không thể sao chép.', 'error'));
  };

  const copyLabel = (btnId: string, icon: string, label: string) =>
    copiedId === btnId ? (
      <>
        <i className="bi bi-check2 mr-1"></i> Đã sao chép!
      </>
    ) : (
      <>
        <i className={`bi ${icon}`}></i> {label}
      </>
    );

  /* ---------- Playground helpers ---------- */

  const resultObj = obj(playgroundResult);
  const resultIsArray = Array.isArray(playgroundResult);
  const isGetTool = ['lookup_scam_db', 'get_scam_radar_trends', 'get_supported_banks'].includes(playgroundTool);

  const getResultRiskScore = (): number => {
    if (typeof resultObj.risk_score === 'number') return resultObj.risk_score;
    if (typeof resultObj.overall_risk_score === 'number') return resultObj.overall_risk_score;
    return 0;
  };

  const getResultRiskLevel = (): RiskKey => {
    const raw = (str(resultObj.risk_level) || str(resultObj.overall_risk_level)).toUpperCase();
    if (['RED', 'CRITICAL', 'HIGH'].includes(raw)) return 'CRITICAL';
    if (['YELLOW', 'MEDIUM', 'WARN', 'WARNING', 'ORANGE'].includes(raw)) return 'WARNING';
    if (['LOW'].includes(raw)) return 'LOW';
    return 'SAFE';
  };

  const getResultThreats = (): string[] => {
    const keys = ['detected_threats', 'details', 'reasons', 'patterns_found', 'security_checks'];
    for (const k of keys) {
      const list = strArr(resultObj[k]);
      if (list.length > 0) return list;
    }
    return [];
  };

  const getResultExplanation = (): string =>
    str(resultObj.explanation) || str(resultObj.analysis_result) || str(resultObj.message) || '';

  const getFilteredBanks = (): Record<string, unknown>[] => {
    if (!Array.isArray(playgroundResult)) return [];
    const list = (playgroundResult as unknown[]).map(obj);
    const q = bankSearchFilter.trim().toLowerCase();
    if (!q) return list.slice(0, 40);
    return list.filter(
      (b) =>
        str(b.shortName).toLowerCase().includes(q) ||
        str(b.name).toLowerCase().includes(q) ||
        str(b.code).toLowerCase().includes(q) ||
        str(b.bin).includes(q),
    );
  };

  const selectTool = (tool: string) => {
    setPlaygroundTool(tool);
    setPlaygroundError(null);
    setPlaygroundResult(null);
    setPlaygroundHttpStatus(null);
    setPlaygroundLatency(0);
    if (tool === 'check_phone' && !playgroundPhone) {
      setPlaygroundPhone('0912345678');
    } else if (tool === 'check_bank_account') {
      if (!playgroundBank) setPlaygroundBank('MB');
      if (!playgroundAccount) setPlaygroundAccount('0987654321');
    } else if (tool === 'check_url_or_domain' && !playgroundUrl) {
      setPlaygroundUrl('http://dichvucong-vn.top/login');
    } else if (tool === 'analyze_message' && !playgroundMessage) {
      setPlaygroundMessage('Ngân hàng MB thông báo tài khoản của quý khách bị tạm khóa do giao dịch bất thường. Vui lòng cung cấp mã OTP để mở khóa.');
    } else if (tool === 'check_email_sender') {
      if (!playgroundEmail) setPlaygroundEmail('support@mbbank-security.top');
      if (!playgroundMessage) setPlaygroundMessage('Yêu cầu nộp lệ phí 500,000 VND để giải ngân khoản vay trực tuyến.');
    } else if (tool === 'scan_full_incident') {
      if (!playgroundPhone) setPlaygroundPhone('0912345678');
      if (!playgroundBank) setPlaygroundBank('MB');
      if (!playgroundAccount) setPlaygroundAccount('0987654321');
      if (!playgroundUrl) setPlaygroundUrl('http://dichvucong-vn.top');
      if (!playgroundMessage) setPlaygroundMessage('Đối tượng gọi mạo danh cán bộ công an yêu cầu chuyển tiền vào STK MBBank 0987654321.');
    } else if (tool === 'lookup_scam_db' && !playgroundQuery) {
      setPlaygroundQuery('0912345678');
    } else if (tool === 'report_scam') {
      if (!playgroundReportTargetValue) setPlaygroundReportTargetValue('0988776655');
      if (!playgroundReportDescription) setPlaygroundReportDescription('Số điện thoại gọi mạo danh công an yêu cầu chuyển tiền bảo lãnh điều tra.');
    }
  };

  const setPreset = (type: string) => {
    setPlaygroundResult(null);
    setPlaygroundError(null);
    if (type === 'sms_otp') {
      setPlaygroundTool('analyze_message');
      setPlaygroundMessage('Ngân hàng MB thông báo tài khoản của quý khách bị phong tỏa do nghi ngờ gian lận. Vui lòng gửi mã OTP xác minh ngay hoặc truy cập http://dichvucong-vn.top để mở khóa.');
    } else if (type === 'bank_scam') {
      setPlaygroundTool('check_bank_account');
      setPlaygroundBank('MB');
      setPlaygroundAccount('0987654321');
    } else if (type === 'phishing_link') {
      setPlaygroundTool('check_url_or_domain');
      setPlaygroundUrl('http://dichvucong-vn.top/login');
    } else if (type === 'fake_email') {
      setPlaygroundTool('check_email_sender');
      setPlaygroundEmail('fraud@phishing-fake-bank.top');
      setPlaygroundMessage('Thông báo yêu cầu nộp tiền bảo lãnh tài khoản ngân hàng khẩn cấp.');
    } else if (type === 'full_incident') {
      setPlaygroundTool('scan_full_incident');
      setPlaygroundPhone('0912345678');
      setPlaygroundBank('MB');
      setPlaygroundAccount('0987654321');
      setPlaygroundUrl('http://dichvucong-vn.top');
      setPlaygroundMessage('Đối tượng gọi mạo danh cơ quan công an yêu cầu chuyển tiền vào STK 0987654321 MB Bank và truy cập http://dichvucong-vn.top.');
    } else if (type === 'db_lookup') {
      setPlaygroundTool('lookup_scam_db');
      setPlaygroundQuery('0912345678');
      setPlaygroundEntityType('all');
    } else if (type === 'radar_trends') {
      setPlaygroundTool('get_scam_radar_trends');
    }
  };

  /* Full incident: tổng hợp 4 nguồn phía client giống bản gốc. */
  const buildFullIncident = async (): Promise<Record<string, unknown>> => {
    const entitiesScanned: Record<string, unknown> = {};
    const allThreats: string[] = [];
    let maxScore = 0;

    const pVal = playgroundPhone.trim();
    const bName = playgroundBank.trim();
    const aVal = playgroundAccount.trim();
    const uVal = playgroundUrl.trim();
    const mVal = playgroundMessage.trim();

    if (!pVal && !aVal && !uVal && !mVal) {
      throw new Error('Vui lòng cung cấp ít nhất một thông tin: Số điện thoại, Tài khoản ngân hàng, URL hoặc Tin nhắn.');
    }

    const safePost = async (path: string, body: unknown, onOk: (d: unknown) => void) => {
      try {
        const d = await api.post<unknown>(path, body);
        onOk(d);
      } catch {
        /* bỏ qua từng nguồn lỗi giống bản gốc (.catch(() => {})) */
      }
    };

    const tasks: Array<Promise<void>> = [];
    if (pVal) {
      tasks.push(
        safePost('/scan/phone/', { phone: pVal }, (d) => {
          entitiesScanned.phone = d;
          const o = obj(d);
          const sc = parseInt(str(o.risk_score) || '0', 10);
          if (sc > maxScore) maxScore = sc;
          const reasons = strArr(o.reasons);
          reasons.forEach((r) => allThreats.push(`[Số điện thoại ${pVal}] ${r}`));
        }),
      );
    }
    if (aVal) {
      tasks.push(
        safePost('/scan/account/', { bank: bName || 'MB', account: aVal }, (d) => {
          entitiesScanned.bank_account = d;
          const o = obj(d);
          const sc = parseInt(str(o.risk_score) || '0', 10);
          if (sc > maxScore) maxScore = sc;
          const details = strArr(o.details);
          details.forEach((r) => allThreats.push(`[Ngân hàng ${bName} ${aVal}] ${r}`));
        }),
      );
    }
    if (uVal) {
      tasks.push(
        safePost('/scan/domain/', { url: uVal }, (d) => {
          entitiesScanned.url = d;
          const o = obj(d);
          const sc = parseInt(str(o.risk_score) || '0', 10);
          if (sc > maxScore) maxScore = sc;
          const details = strArr(o.details);
          details.forEach((r) => allThreats.push(`[Tên miền ${uVal}] ${r}`));
        }),
      );
    }
    if (mVal) {
      tasks.push(
        safePost('/scan/message/', { message: mVal, sync: true }, (d) => {
          entitiesScanned.message = d;
          const o = obj(d);
          const sc = parseInt(str(o.risk_score) || '0', 10);
          if (sc > maxScore) maxScore = sc;
          const patterns = strArr(o.patterns_found);
          patterns.forEach((r) => allThreats.push(`[Tin nhắn] ${r}`));
        }),
      );
    }

    await Promise.all(tasks);

    let overallLevel = 'SAFE';
    if (maxScore >= 80) overallLevel = 'CRITICAL';
    else if (maxScore >= 50) overallLevel = 'MEDIUM';
    else if (maxScore >= 20) overallLevel = 'LOW';

    const recommendedActions: string[] = [];
    if (maxScore >= 80) {
      recommendedActions.push('CHẶN KHẨN CẤP: Tuyệt đối không chuyển tiền hoặc cung cấp mã OTP/thông tin cá nhân.');
      recommendedActions.push('Liên hệ đường dây nóng ngân hàng để tạm khóa tài khoản hoặc thẻ thanh toán nếu đã cung cấp thông tin.');
      recommendedActions.push('Thu thập bằng chứng và gửi báo cáo lừa đảo qua công cụ report_scam.');
    } else if (maxScore >= 50) {
      recommendedActions.push('CẢNH GIÁC CAO ĐỘ: Phát hiện tín hiệu bất thường về hạ tầng hoặc dấu hiệu bẫy tâm lý mạo danh.');
      recommendedActions.push('Xác minh độc lập qua kênh tổng đài chính thức của đơn vị trước khi giao dịch.');
    } else {
      recommendedActions.push('Không ghi nhận chỉ số đe dọa trực tiếp. Tiếp tục duy trì nguyên tắc an toàn thông tin cơ bản.');
    }

    return {
      overall_risk_score: maxScore,
      overall_risk_level: overallLevel,
      entities_scanned: entitiesScanned,
      detected_threats: allThreats,
      recommended_actions: recommendedActions,
      entities_count: Object.keys(entitiesScanned).length,
    };
  };

  const runPlayground = async () => {
    if (playgroundLoading) return;
    setPlaygroundLoading(true);
    setPlaygroundResult(null);
    setPlaygroundError(null);
    setPlaygroundLatency(0);
    setPlaygroundHttpStatus(null);
    const startTime = performance.now();

    try {
      let data: unknown;
      if (playgroundTool === 'check_phone') {
        const phone = playgroundPhone.trim();
        if (!phone) {
          setPlaygroundError('Vui lòng nhập số điện thoại cần quét.');
          return;
        }
        data = await api.post('/scan/phone/', { phone });
      } else if (playgroundTool === 'check_bank_account') {
        const bank = playgroundBank.trim();
        const account = playgroundAccount.trim();
        if (!bank || !account) {
          setPlaygroundError('Vui lòng nhập tên ngân hàng và số tài khoản.');
          return;
        }
        data = await api.post('/scan/account/', { bank, account });
      } else if (playgroundTool === 'check_url_or_domain') {
        const url = playgroundUrl.trim();
        if (!url) {
          setPlaygroundError('Vui lòng nhập URL hoặc tên miền.');
          return;
        }
        data = await api.post('/scan/domain/', { url });
      } else if (playgroundTool === 'analyze_message') {
        const message = playgroundMessage.trim();
        if (!message) {
          setPlaygroundError('Vui lòng nhập nội dung tin nhắn.');
          return;
        }
        data = await api.post('/scan/message/', { message, sync: true });
      } else if (playgroundTool === 'check_email_sender') {
        const senderEmail = playgroundEmail.trim();
        if (!senderEmail) {
          setPlaygroundError('Vui lòng nhập địa chỉ email người gửi.');
          return;
        }
        data = await api.post('/scan/email/', {
          sender_email: senderEmail,
          email_content: playgroundMessage.trim(),
          sync: true,
        });
      } else if (playgroundTool === 'get_supported_banks') {
        data = await api.get('/scan/banks/');
      } else if (playgroundTool === 'lookup_scam_db') {
        const q = encodeURIComponent(playgroundQuery.trim());
        const t = encodeURIComponent(playgroundEntityType || 'all');
        data = await api.get(`/scan/lookup/?q=${q}&type=${t}`);
      } else if (playgroundTool === 'get_scam_radar_trends') {
        data = await api.get('/trends/radar-stats/');
      } else if (playgroundTool === 'report_scam') {
        const targetValue = playgroundReportTargetValue.trim();
        const description = playgroundReportDescription.trim();
        if (!targetValue || !description) {
          setPlaygroundError('Vui lòng nhập mục tiêu bị báo cáo và nội dung mô tả chi tiết.');
          return;
        }
        data = await api.post('/report/', {
          target_type: playgroundReportTargetType || 'phone',
          target_value: targetValue,
          scam_type: playgroundReportScamType || 'other',
          description,
        });
      } else if (playgroundTool === 'scan_full_incident') {
        data = await buildFullIncident();
      }

      setPlaygroundHttpStatus(200);
      setPlaygroundLatency(Math.round(performance.now() - startTime));
      setPlaygroundResult(data ?? null);
    } catch (err) {
      setPlaygroundLatency(Math.round(performance.now() - startTime));
      setPlaygroundHttpStatus(err instanceof ApiError ? err.status : null);
      setPlaygroundError(err instanceof Error ? err.message : 'Lỗi kết nối máy chủ ShieldCall.');
    } finally {
      setPlaygroundLoading(false);
      if (typeof window !== 'undefined' && window.innerWidth < 1024) {
        window.requestAnimationFrame(() => {
          document.getElementById('playground-console')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
      }
    }
  };

  const riskLevel = getResultRiskLevel();
  const riskUi = RISK_UI[riskLevel];
  const threats = getResultThreats();
  const explanation = getResultExplanation();
  const recommendedActions = strArr(resultObj.recommended_actions);
  const filteredBanks = getFilteredBanks();
  const bankTotal = resultIsArray ? (playgroundResult as unknown[]).length : 0;
  const hotPhones = arr(resultObj.hot_phones);
  const topScamTypes = arr(resultObj.top_scam_types);
  const lookupItems = arr(resultObj.results);
  const pctChange = num(resultObj.pct_change);

  return (
    <div className="max-w-7xl mx-auto space-y-12 py-6 pb-28 px-4 sm:px-6 lg:px-8">
      {/* Hero Banner */}
      <div className="relative overflow-hidden rounded-3xl border border-white/10 bg-gradient-to-b from-brand-500/10 via-white/[0.02] to-transparent p-8 md:p-12">
        <div className="absolute -top-24 -right-24 w-96 h-96 bg-brand-500/20 rounded-full blur-3xl pointer-events-none"></div>
        <div className="absolute -bottom-24 -left-24 w-96 h-96 bg-brand2-500/15 rounded-full blur-3xl pointer-events-none"></div>

        <div className="relative z-10 max-w-4xl space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-brand-400/10 border border-brand-400/25 text-brand-300 text-xs font-black uppercase tracking-widest">
            <i className="bi bi-cpu-fill"></i> Model Context Protocol • Chuẩn Mở Toàn Cầu
          </div>
          <h1 className="text-3xl sm:text-5xl font-black text-white tracking-tight leading-tight">
            Biến Mọi Chatbot Thành <span className="glow-text text-brand-400">Chuyên Gia An Ninh Số</span> ShieldCall
          </h1>
          <p className="text-white/70 text-base sm:text-lg leading-relaxed">
            Kết nối trực tiếp toàn bộ kho dữ liệu lừa đảo, công cụ kiểm tra số điện thoại rủi ro, đối soát tài khoản ngân hàng gian lận và phát hiện website giả mạo của <strong>ShieldCall VN</strong> vào bất kỳ AI nào: <strong>Claude Desktop, Cursor, Windsurf, Claude Code, Cline, ChatGPT</strong>.
          </p>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <a href="#quick-config" className="liquid-btn py-3 px-5 text-xs font-black bg-brand-400 text-black hover:bg-brand-300 uppercase tracking-widest shadow-lg shadow-brand-400/20">
              <i className="bi bi-gear-wide-connected mr-1.5"></i> Cấu Hình Ngay
            </a>
            <a href="/mcp/download/" download="shieldcall_mcp.py" className="liquid-btn py-3 px-5 text-xs font-black bg-white/10 text-brand-300 hover:bg-white/15 border border-brand-400/30 uppercase tracking-widest">
              <i className="bi bi-download mr-1.5"></i> Tải Script Python
            </a>
            <a href="#live-playground" className="liquid-btn py-3 px-5 text-xs font-black bg-white/10 text-white hover:bg-white/15 border border-white/10 uppercase tracking-widest">
              <i className="bi bi-play-circle-fill mr-1.5"></i> Thử Nghiệm Live
            </a>
            <a href="#starter-prompts" className="liquid-btn py-3 px-5 text-xs font-black bg-white/5 text-white/70 hover:text-white border border-white/10 uppercase tracking-widest">
              <i className="bi bi-chat-square-quote mr-1.5"></i> Mẫu Prompt
            </a>
            <a href="#tools-reference" className="liquid-btn py-3 px-5 text-xs font-black bg-white/5 text-white/70 hover:text-white border border-white/10 uppercase tracking-widest">
              <i className="bi bi-tools mr-1.5"></i> 10 Công Cụ
            </a>
            <a href="#troubleshooting" className="liquid-btn py-3 px-5 text-xs font-black bg-white/5 text-white/70 hover:text-white border border-white/10 uppercase tracking-widest">
              <i className="bi bi-question-circle mr-1.5"></i> FAQ & Khắc Phục Lỗi
            </a>
          </div>
        </div>
      </div>

      {/* API Key Active Selector Bar */}
      <div className="liquid-card p-6 border border-brand-500/25 bg-brand-500/[0.03] rounded-3xl">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div className="space-y-1 max-w-xl">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-brand-400 animate-pulse"></span>
              <h3 className="text-sm font-black text-white uppercase tracking-wider">Khóa API Tích Hợp Của Bạn</h3>
            </div>
            <p className="text-xs text-white/60 leading-relaxed">
              Mã khóa được nhúng trực tiếp vào các file cấu hình bên dưới để bạn chỉ việc sao chép và kích hoạt.
            </p>
          </div>

          <div className="w-full lg:w-auto">
            {user ? (
              activeKeys.length > 0 ? (
                <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-white/70 whitespace-nowrap">Chọn khóa:</span>
                    <select
                      value={effectiveSelectedKey}
                      onChange={(e) => setSelectedKey(e.target.value)}
                      className="bg-black/80 border border-brand-400/30 rounded-xl px-3.5 py-2 text-xs font-mono text-brand-300 focus:outline-none focus:border-brand-400"
                    >
                      {activeKeys.map((k) => (
                        <option key={k.id} value={`${k.prefix}_secret_key_here`}>
                          {k.name} ({k.prefix}...)
                        </option>
                      ))}
                    </select>
                  </div>
                  <Link href="/dashboard/?tab=api_keys" className="px-4 py-2 rounded-xl text-xs font-bold bg-white/10 text-white hover:bg-white/20 border border-white/15 transition-all flex items-center gap-1.5 whitespace-nowrap">
                    <i className="bi bi-gear"></i> Quản lý khóa
                  </Link>
                </div>
              ) : (
                <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
                  <span className="text-xs text-warn-300 flex items-center gap-1.5 whitespace-nowrap">
                    <i className="bi bi-exclamation-triangle-fill"></i> Bạn chưa tạo API Key nào
                  </span>
                  <Link href="/dashboard/?tab=api_keys" className="px-4 py-2 rounded-xl text-xs font-black bg-brand-400 text-black hover:bg-brand-300 transition-all uppercase tracking-wider shadow-lg shadow-brand-400/20 whitespace-nowrap">
                    Tạo API Key (500 req/ngày)
                  </Link>
                </div>
              )
            ) : (
              <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3.5">
                <span className="text-xs text-white/70 whitespace-nowrap">Đăng nhập để tự động điền API Key thực của bạn:</span>
                <div className="flex items-center gap-2 shrink-0">
                  <Link href="/login/?next=/mcp/" className="px-4 py-2 rounded-xl text-xs font-bold bg-white/10 hover:bg-white/20 text-white border border-white/15 transition-all text-center">
                    Đăng nhập
                  </Link>
                  <Link href="/register/?next=/mcp/" className="px-4 py-2 rounded-xl text-xs font-black bg-brand-400 hover:bg-brand-300 text-black transition-all uppercase tracking-wider shadow-lg shadow-brand-400/20 text-center">
                    Đăng ký miễn phí
                  </Link>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Architecture Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="liquid-card p-6 space-y-3 bg-white/[0.02]">
          <div className="w-10 h-10 rounded-xl bg-brand-500/10 text-brand-400 flex items-center justify-center text-lg">
            <i className="bi bi-robot"></i>
          </div>
          <h3 className="text-base font-bold text-white">1. Mọi Chatbot Thương Mại</h3>
          <p className="text-xs text-white/60 leading-relaxed">
            Người dùng trò chuyện bình thường với Claude, Cursor, ChatGPT. Khi người dùng đề cập đến SĐT, STK, link hoặc tin nhắn lạ, AI sẽ nhận diện ngữ cảnh.
          </p>
        </div>

        <div className="liquid-card p-6 space-y-3 bg-white/[0.02] border-brand-500/20">
          <div className="w-10 h-10 rounded-xl bg-brand2-500/10 text-brand2-400 flex items-center justify-center text-lg">
            <i className="bi bi-arrow-left-right"></i>
          </div>
          <h3 className="text-base font-bold text-white">2. Giao Thức Chuẩn MCP</h3>
          <p className="text-xs text-white/60 leading-relaxed">
            Chatbot tự động gọi các tool chuẩn hóa qua giao thức Model Context Protocol (Stdio / SSE), chuyển tiếp tham số tới ShieldCall MCP Server an toàn.
          </p>
        </div>

        <div className="liquid-card p-6 space-y-3 bg-white/[0.02]">
          <div className="w-10 h-10 rounded-xl bg-safe-500/10 text-safe-400 flex items-center justify-center text-lg">
            <i className="bi bi-shield-check"></i>
          </div>
          <h3 className="text-base font-bold text-white">3. Cơ Sở Dữ Liệu An Ninh Số</h3>
          <p className="text-xs text-white/60 leading-relaxed">
            ShieldCall đối soát danh sách đen, điểm tín nhiệm rủi ro, phân tích tên miền nhái, và trả về kết quả thời gian thực để AI cảnh báo người dùng.
          </p>
        </div>
      </div>

      {/* Integration Setup Guide Tabs */}
      <div id="quick-config" className="space-y-6 pt-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
          <div>
            <h2 className="text-2xl font-black text-white tracking-tight">Hướng Dẫn Cấu Hình Từng Nền Tảng</h2>
            <p className="text-xs text-white/60">Chọn ứng dụng bạn đang sử dụng để xem hướng dẫn chi tiết và file cấu hình 1-click copy.</p>
          </div>

          {/* Platform Tabs */}
          <div className="flex flex-wrap gap-2 p-1 bg-black/40 border border-white/10 rounded-2xl">
            {PLATFORMS.map((p) => (
              <button
                key={p.id}
                onClick={() => setActivePlatform(p.id)}
                className={`px-4 py-2 rounded-xl text-xs font-black transition-all flex items-center gap-1.5 ${
                  activePlatform === p.id ? 'bg-brand-400 text-black shadow-lg shadow-brand-400/20' : 'text-white/60 hover:text-white'
                }`}
              >
                {p.pulse && <span className="w-2 h-2 rounded-full bg-safe-400 animate-pulse"></span>}
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* Standalone Script Download & Global Config Parameters */}
        <div className="liquid-card p-6 border border-brand-500/30 bg-gradient-to-br from-brand-500/[0.05] via-white/[0.02] to-transparent rounded-3xl space-y-5">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-white/10 pb-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-brand-400"></span>
                <h3 className="text-sm font-black text-white uppercase tracking-wider">Tải Script Python Độc Lập (Standalone MCP)</h3>
                <span className="px-2 py-0.5 rounded-full bg-brand-400/10 text-brand-300 border border-brand-400/20 text-[10px] font-bold">1 file ~24KB</span>
              </div>
              <p className="text-xs text-white/60 leading-relaxed">
                Bạn <strong>không cần clone toàn bộ repository</strong> hay cài đặt mã nguồn dự án. Script chứa đầy đủ MCP server, công cụ an ninh và kết nối bảo mật tới ShieldCall API.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2.5 shrink-0">
              <a href="/mcp/download/" download="shieldcall_mcp.py" className="liquid-btn py-2.5 px-4 text-xs font-black bg-brand-400 text-black hover:bg-brand-300 uppercase tracking-wider flex items-center gap-2 shadow-lg shadow-brand-400/20">
                <i className="bi bi-download"></i> Tải Script (.py)
              </a>
              <a href="/mcp/download/?raw=1" target="_blank" rel="noopener noreferrer" className="liquid-btn py-2.5 px-3.5 text-xs font-bold bg-white/10 text-white hover:bg-white/20 border border-white/15 flex items-center gap-1.5">
                <i className="bi bi-code-slash"></i> Xem mã nguồn Raw
              </a>
            </div>
          </div>

          {/* Terminal Download & Zero-Dependency Badge */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="space-y-1.5">
              <span className="text-[10px] font-bold text-white/60 uppercase tracking-wider block">Lệnh tải file script bằng Terminal:</span>
              <div className="flex items-center gap-2">
                <code className="flex-1 p-2.5 bg-black/60 border border-white/10 rounded-xl text-brand-300 select-all text-[11px]">
                  {`curl -sSL ${origin || SITE_URL}/mcp/download/ -o shieldcall_mcp.py`}
                </code>
                <button
                  onClick={() =>
                    copyText(
                      `curl -sSL ${origin || SITE_URL}/mcp/download/ -o shieldcall_mcp.py`,
                      'btn-curl'
                    )
                  }
                  id="btn-curl"
                  className="p-2.5 rounded-xl bg-white/10 hover:bg-white/20 text-white text-xs shrink-0"
                  title="Sao chép"
                >
                  {copiedId === 'btn-curl' ? <><i className="bi bi-check2 mr-1"></i> Đã sao chép!</> : <i className="bi bi-clipboard"></i>}
                </button>
              </div>
            </div>
            <div className="space-y-1.5">
              <span className="text-[10px] font-bold text-safe-400 uppercase tracking-wider block flex items-center gap-1.5">
                <i className="bi bi-check-circle-fill text-safe-400"></i> Độc lập 100% (Zero-Dependency):
              </span>
              <div className="p-2.5 bg-safe-500/10 border border-safe-500/20 rounded-xl text-safe-300 text-[11px] flex items-center justify-between">
                <span>Chạy trực tiếp với Python 3 có sẵn. Không cần chạy <code>pip install</code>.</span>
                <span className="px-2 py-0.5 rounded-md bg-safe-400/20 text-safe-300 font-mono text-[10px] font-bold shrink-0 ml-2">Python 3.8+</span>
              </div>
            </div>
          </div>

          {/* Dynamic Path Config Inputs */}
          <div className="pt-2 border-t border-white/10 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-white/80 flex items-center justify-between">
                <span>Đường dẫn file script trên máy bạn (scriptPath):</span>
                <span className="text-[10px] font-normal text-brand-400">Tự động cập nhật vào JSON</span>
              </label>
              <input
                type="text"
                value={scriptPath}
                onChange={(e) => setScriptPath(e.target.value)}
                placeholder="shieldcall_mcp.py hoặc /path/to/shieldcall_mcp.py"
                className="w-full bg-black/60 border border-brand-400/30 rounded-xl px-3.5 py-2 text-xs font-mono text-brand-300 focus:outline-none focus:border-brand-400"
              />
              <p className="text-[11px] text-white/55">Nếu đặt cùng thư mục workspace bạn chỉ cần để <code>shieldcall_mcp.py</code>, hoặc điền đường dẫn tuyệt đối.</p>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-white/80 flex items-center justify-between">
                <span>Lệnh Python (pythonPath):</span>
                <span className="text-[10px] font-normal text-brand-400">Tự động cập nhật vào JSON</span>
              </label>
              <input
                type="text"
                value={pythonPath}
                onChange={(e) => setPythonPath(e.target.value)}
                placeholder="python hoặc python3 hoặc C:\Python311\python.exe"
                className="w-full bg-black/60 border border-brand-400/30 rounded-xl px-3.5 py-2 text-xs font-mono text-brand-300 focus:outline-none focus:border-brand-400"
              />
              <p className="text-[11px] text-white/55">Mặc định là <code>python</code>. Nếu dùng macOS/Linux có thể đổi thành <code>python3</code>.</p>
            </div>
          </div>
        </div>

        {/* Tab 0: Claude Chat (Web & Mobile Custom Connector) */}
        {activePlatform === 'claude_chat' && (
          <div className="space-y-6">
            <div className="liquid-card p-6 space-y-6 border-brand-400/30 bg-gradient-to-br from-brand-500/[0.04] via-white/[0.02] to-transparent">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-white/10 pb-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="text-lg font-black text-white flex items-center gap-2">
                      <i className="bi bi-chat-square-quote-fill text-brand-400"></i> Claude Chat (claude.ai Web & Mobile)
                    </h3>
                    <span className="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-safe-500/20 text-safe-300 border border-safe-500/30">
                      Remote MCP Connector
                    </span>
                  </div>
                  <p className="text-xs text-white/60">
                    Kết nối trực tiếp ShieldCall vào tài khoản <strong>claude.ai</strong> trên trình duyệt và ứng dụng điện thoại (iOS / Android) mà <strong>không cần cài Python hay chạy script máy khách</strong>.
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] font-mono bg-white/10 px-3 py-1.5 rounded-xl text-white/80 border border-white/15">
                    Transport: Server-Sent Events (SSE)
                  </span>
                </div>
              </div>

              {/* 1-Click Remote MCP URL Box */}
              <div className="p-5 rounded-2xl bg-black/60 border border-brand-400/30 space-y-3 shadow-inner">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <span className="text-xs font-black text-brand-300 uppercase tracking-wider flex items-center gap-1.5">
                    <i className="bi bi-link-45deg text-base"></i> Đường dẫn MCP Server URL (Dán vào Claude):
                  </span>
                  <span className="text-[11px] text-white/60">Tự động gắn API Key thực đã chọn ở thanh trên cùng</span>
                </div>
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
                  <input
                    type="text"
                    readOnly
                    value={getClaudeChatConnectorUrl()}
                    className="flex-1 p-3 bg-white/5 border border-white/15 rounded-xl font-mono text-xs text-brand-300 select-all focus:outline-none focus:border-brand-400"
                  />
                  <button
                    onClick={() => copyText(getClaudeChatConnectorUrl(), 'claude-chat-url-btn')}
                    id="claude-chat-url-btn"
                    className="liquid-btn py-3 px-5 text-xs font-black bg-brand-400 text-black hover:bg-brand-300 uppercase tracking-wider flex items-center justify-center gap-2 shadow-lg shadow-brand-400/20 shrink-0"
                  >
                    {copyLabel('claude-chat-url-btn', 'bi-clipboard', 'Sao chép URL')}
                  </button>
                </div>
                <div className="flex flex-wrap items-center gap-3 text-[11px] text-white/60 pt-1">
                  <span className="flex items-center gap-1 text-safe-400 font-bold">
                    <i className="bi bi-check-circle-fill"></i> Hỗ trợ cả tài khoản Free, Pro, Team, Enterprise
                  </span>
                  <span className="text-white/35">•</span>
                  <span>Đã mã hóa bảo mật chuẩn HTTPS (SSL/TLS)</span>
                </div>
              </div>

              {/* Step by step instructions matching Claude UI */}
              <div className="space-y-4">
                <h4 className="text-xs font-black text-white uppercase tracking-wider flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-brand-400"></span>
                  4 Bước Cấu Hình Trong Claude Chat (claude.ai):
                </h4>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Step 1 */}
                  <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 space-y-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-6 h-6 rounded-full bg-brand-400/20 text-brand-300 flex items-center justify-center font-black text-xs shrink-0">1</span>
                      <h5 className="text-xs font-bold text-white">Mở mục Connectors trong Claude</h5>
                    </div>
                    <p className="text-[11px] text-white/60 leading-relaxed pl-8">
                      Truy cập <a href="https://claude.ai" target="_blank" rel="noopener noreferrer" className="text-brand-400 hover:underline">claude.ai</a> -&gt; Nhấp vào biểu tượng <strong>Tài khoản (Avatar góc dưới bên trái)</strong> -&gt; Chọn <strong>Settings</strong> (hoặc Customize) -&gt; Chọn thẻ <strong>Connectors</strong>.
                    </p>
                  </div>

                  {/* Step 2 */}
                  <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 space-y-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-6 h-6 rounded-full bg-brand-400/20 text-brand-300 flex items-center justify-center font-black text-xs shrink-0">2</span>
                      <h5 className="text-xs font-bold text-white">Thêm Custom Connector</h5>
                    </div>
                    <p className="text-[11px] text-white/60 leading-relaxed pl-8">
                      Nhấp vào nút <strong>Add custom connector</strong>. Cửa sổ thiết lập Model Context Protocol sẽ hiển thị trên màn hình.
                    </p>
                  </div>

                  {/* Step 3 */}
                  <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 space-y-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-6 h-6 rounded-full bg-brand-400/20 text-brand-300 flex items-center justify-center font-black text-xs shrink-0">3</span>
                      <h5 className="text-xs font-bold text-white">Điền thông tin máy chủ ShieldCall</h5>
                    </div>
                    <div className="text-[11px] text-white/60 space-y-1.5 pl-8">
                      <div>• <strong>Name:</strong> Nhập <code className="text-brand-300">ShieldCall VN</code></div>
                      <div>• <strong>MCP server URL:</strong> Dán đường link ở khung màu đen phía trên.</div>
                      <div className="text-white/55 text-[10px]">* Hoặc bấm Advanced settings -&gt; Thêm header <code>X-API-Key</code>.</div>
                    </div>
                  </div>

                  {/* Step 4 */}
                  <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 space-y-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-6 h-6 rounded-full bg-safe-400/20 text-safe-300 flex items-center justify-center font-black text-xs shrink-0">4</span>
                      <h5 className="text-xs font-bold text-white">Bấm "Add connector" để kích hoạt</h5>
                    </div>
                    <p className="text-[11px] text-white/60 leading-relaxed pl-8">
                      Claude sẽ tự động bắt tay với ShieldCall qua HTTPS, nạp toàn bộ 10 công cụ an ninh số. Giờ đây mọi câu hỏi về SĐT, STK, link lừa đảo sẽ được AI tự động kiểm tra!
                    </p>
                  </div>
                </div>
              </div>

              {/* Interactive Test Prompts */}
              <div className="p-5 rounded-2xl bg-white/[0.02] border border-white/10 space-y-3">
                <p className="text-xs font-bold text-white/80 flex items-center gap-2">
                  <i className="bi bi-lightning-charge-fill text-warn-400"></i> Câu lệnh mẫu bạn có thể chat thử nghiệm ngay với Claude:
                </p>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="p-3 bg-black/40 rounded-xl border border-white/10 text-xs space-y-2 flex flex-col justify-between">
                    <p className="text-white/70 italic text-[11px]">"Kiểm tra số điện thoại 0912345678 giúp tôi xem có lịch sử lừa đảo hay cuộc gọi rác không."</p>
                    <button
                      onClick={() => copyText('Kiểm tra số điện thoại 0912345678 giúp tôi xem có lịch sử lừa đảo hay cuộc gọi rác không.', 'prompt-test-1')}
                      id="prompt-test-1"
                      className="text-[10px] text-brand-400 hover:text-brand-300 font-bold self-end flex items-center gap-1"
                    >
                      {copyLabel('prompt-test-1', 'bi-clipboard', 'Sao chép')}
                    </button>
                  </div>
                  <div className="p-3 bg-black/40 rounded-xl border border-white/10 text-xs space-y-2 flex flex-col justify-between">
                    <p className="text-white/70 italic text-[11px]">"Kiểm tra tài khoản Techcombank 1903654321 xem có nằm trong danh sách đen tài chính không."</p>
                    <button
                      onClick={() => copyText('Kiểm tra tài khoản Techcombank 1903654321 xem có nằm trong danh sách đen tài chính không.', 'prompt-test-2')}
                      id="prompt-test-2"
                      className="text-[10px] text-brand-400 hover:text-brand-300 font-bold self-end flex items-center gap-1"
                    >
                      {copyLabel('prompt-test-2', 'bi-clipboard', 'Sao chép')}
                    </button>
                  </div>
                  <div className="p-3 bg-black/40 rounded-xl border border-white/10 text-xs space-y-2 flex flex-col justify-between">
                    <p className="text-white/70 italic text-[11px]">"Phân tích đường link dichvucong-vn.top xem có phải tên miền nhái giả mạo cổng dịch vụ công không."</p>
                    <button
                      onClick={() => copyText('Phân tích đường link dichvucong-vn.top xem có phải tên miền nhái giả mạo cổng dịch vụ công không.', 'prompt-test-3')}
                      id="prompt-test-3"
                      className="text-[10px] text-brand-400 hover:text-brand-300 font-bold self-end flex items-center gap-1"
                    >
                      {copyLabel('prompt-test-3', 'bi-clipboard', 'Sao chép')}
                    </button>
                  </div>
                </div>
              </div>

              {/* Multi-Chatbot Compatibility Notice */}
              <div className="p-4 rounded-xl bg-brand2-500/10 border border-brand2-500/20 text-xs text-white/70 flex items-start gap-3">
                <i className="bi bi-layers text-brand2-400 text-base shrink-0 mt-0.5"></i>
                <div className="space-y-1">
                  <p className="font-bold text-brand2-300">Tương thích với các Chatbot khác hỗ trợ Remote MCP:</p>
                  <p className="text-[11px] leading-relaxed">
                    Cùng đường dẫn Remote MCP trên, bạn cũng có thể cấu hình cho <strong>Open WebUI</strong>, <strong>LibreChat</strong>, <strong>Dify AI</strong>, hoặc bất kỳ hệ thống chatbot nào hỗ trợ giao thức <strong>MCP SSE / Streamable HTTP</strong>.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 1: Claude Desktop */}
        {activePlatform === 'claude' && (
          <div className="space-y-6">
            <div className="liquid-card p-6 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <i className="bi bi-laptop text-brand-400"></i> Cấu hình Claude Desktop
                  </h3>
                  <p className="text-xs text-white/60">Mở ứng dụng Claude Desktop trên máy tính và cập nhật file cấu hình MCP.</p>
                </div>
                <span className="text-[10px] font-mono bg-white/10 px-2.5 py-1 rounded-md text-white/70">claude_desktop_config.json</span>
              </div>

              <DownloadPrereq label="Tải file script (1 file duy nhất):" zeroDepText="Chạy trực tiếp bằng Python 3, không cần cài đặt bất kỳ thư viện bên ngoài nào." />
              <p className="text-[11px] text-white/60">Sau khi tải xong, ghi nhớ đường dẫn file <code className="text-brand-300">shieldcall_mcp.py</code> và cập nhật vào ô <strong className="text-white">scriptPath</strong> ở thanh công cụ phía trên nếu cần.</p>

              <div className="space-y-2">
                <p className="text-xs font-bold text-white/80">Vị trí file cấu hình:</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-3 bg-black/50 border border-white/10 rounded-xl">
                    <span className="text-brand-400 font-bold block mb-1">macOS:</span>
                    <span className="text-white/70 select-all">~/Library/Application Support/Claude/claude_desktop_config.json</span>
                  </div>
                  <div className="p-3 bg-black/50 border border-white/10 rounded-xl">
                    <span className="text-brand-400 font-bold block mb-1">Windows:</span>
                    <span className="text-white/70 select-all">%APPDATA%\Claude\claude_desktop_config.json</span>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-bold text-white/80">Nội dung cấu hình JSON:</p>
                  <button onClick={() => copyText(getClaudeConfig(), 'claude-btn')} id="claude-btn" className="text-xs font-bold text-brand-400 hover:text-brand-300 flex items-center gap-1">
                    {copyLabel('claude-btn', 'bi-clipboard', 'Sao chép JSON')}
                  </button>
                </div>
                <pre className="bg-[var(--sc-ink-deep)] p-4 rounded-2xl border border-white/10 font-mono text-xs text-brand-300 overflow-x-auto select-all"><code>{getClaudeConfig()}</code></pre>
              </div>

              <div className="p-4 rounded-xl bg-brand-400/5 border border-brand-400/20 text-xs text-white/70 space-y-1">
                <p className="font-bold text-brand-300"><i className="bi bi-info-circle mr-1"></i> Lưu ý sau khi cấu hình:</p>
                <p>Khởi động lại ứng dụng Claude Desktop. Bạn sẽ thấy biểu tượng chiếc búa (Hammer icon) xuất hiện ở góc soạn thảo tin nhắn, hiển thị 7 công cụ bảo mật của ShieldCall.</p>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Cursor IDE */}
        {activePlatform === 'cursor' && (
          <div className="space-y-6">
            <div className="liquid-card p-6 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <i className="bi bi-code-slash text-brand-400"></i> Cấu hình Cursor IDE
                  </h3>
                  <p className="text-xs text-white/60">Tích hợp vào Cursor để kiểm tra an toàn link, sđt, tài khoản ngân hàng ngay trong trình soạn thảo code.</p>
                </div>
                <span className="text-[10px] font-mono bg-white/10 px-2.5 py-1 rounded-md text-white/70">.cursor/mcp.json</span>
              </div>

              <DownloadPrereq label="Tải file script vào thư mục dự án:" zeroDepText="Không cần cài thư viện qua pip. Chạy trực tiếp bằng Python 3." />

              <div className="space-y-2">
                <p className="text-xs font-bold text-white/80">Cách 1: Thêm trực tiếp file <code>.cursor/mcp.json</code> vào thư mục dự án:</p>
                <div className="flex items-center justify-between pt-1">
                  <span className="text-xs text-white/60">File cấu hình trong workspace:</span>
                  <button onClick={() => copyText(getCursorConfig(), 'cursor-btn')} id="cursor-btn" className="text-xs font-bold text-brand-400 hover:text-brand-300 flex items-center gap-1">
                    {copyLabel('cursor-btn', 'bi-clipboard', 'Sao chép .cursor/mcp.json')}
                  </button>
                </div>
                <pre className="bg-[var(--sc-ink-deep)] p-4 rounded-2xl border border-white/10 font-mono text-xs text-brand-300 overflow-x-auto select-all"><code>{getCursorConfig()}</code></pre>
              </div>

              <div className="space-y-2">
                <p className="text-xs font-bold text-white/80">Cách 2: Cấu hình qua Giao diện Cursor Settings:</p>
                <ol className="list-decimal list-inside space-y-1 text-xs text-white/70 pl-2">
                  <li>Mở <strong>Cursor Settings</strong> (Ctrl+, hoặc Cmd+,) → chọn tab <strong>Features</strong> → <strong>MCP Servers</strong>.</li>
                  <li>Bấm <strong>Add New MCP Server</strong>.</li>
                  <li>Điền Name: <code>shieldcall</code>, Type: <code>command</code>, Command: <code>python shieldcall_mcp.py</code> (hoặc điền đường dẫn tuyệt đối tới file đã tải).</li>
                </ol>
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: Windsurf */}
        {activePlatform === 'windsurf' && (
          <div className="space-y-6">
            <div className="liquid-card p-6 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <i className="bi bi-water text-brand-400"></i> Cấu hình Windsurf (Codeium)
                  </h3>
                  <p className="text-xs text-white/60">Cấu hình file MCP cho trợ lý AI Cascade trong Windsurf.</p>
                </div>
                <span className="text-[10px] font-mono bg-white/10 px-2.5 py-1 rounded-md text-white/70">~/.codeium/windsurf/mcp_config.json</span>
              </div>

              <DownloadPrereq label="Tải file script vào máy:" zeroDepText="Không cần cài thư viện qua pip. Chạy trực tiếp bằng Python 3." />

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-bold text-white/80">Nội dung cấu hình:</p>
                  <button onClick={() => copyText(getWindsurfConfig(), 'windsurf-btn')} id="windsurf-btn" className="text-xs font-bold text-brand-400 hover:text-brand-300 flex items-center gap-1">
                    {copyLabel('windsurf-btn', 'bi-clipboard', 'Sao chép mcp_config.json')}
                  </button>
                </div>
                <pre className="bg-[var(--sc-ink-deep)] p-4 rounded-2xl border border-white/10 font-mono text-xs text-brand-300 overflow-x-auto select-all"><code>{getWindsurfConfig()}</code></pre>
              </div>
            </div>
          </div>
        )}

        {/* Tab 4: Claude Code CLI */}
        {activePlatform === 'claude_code' && (
          <div className="space-y-6">
            <div className="liquid-card p-6 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <i className="bi bi-terminal text-brand-400"></i> Claude Code CLI
                  </h3>
                  <p className="text-xs text-white/60">Lệnh 1 dòng duy nhất để thêm ShieldCall MCP vào công cụ dòng lệnh Claude Code.</p>
                </div>
                <span className="text-[10px] font-mono bg-white/10 px-2.5 py-1 rounded-md text-white/70">claude mcp add</span>
              </div>

              <DownloadPrereq label="Tải file script vào máy:" zeroDepText="Không cần cài thư viện qua pip. Chạy trực tiếp bằng Python 3." />

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-bold text-white/80">Lệnh Terminal:</p>
                  <button onClick={() => copyText(getClaudeCodeCommand(), 'claudecode-btn')} id="claudecode-btn" className="text-xs font-bold text-brand-400 hover:text-brand-300 flex items-center gap-1">
                    {copyLabel('claudecode-btn', 'bi-clipboard', 'Sao chép lệnh')}
                  </button>
                </div>
                <pre className="bg-[var(--sc-ink-deep)] p-4 rounded-2xl border border-white/10 font-mono text-xs text-brand-300 overflow-x-auto select-all"><code>{getClaudeCodeCommand()}</code></pre>
              </div>
            </div>
          </div>
        )}

        {/* Tab 5: Cline / Roo Code */}
        {activePlatform === 'cline' && (
          <div className="space-y-6">
            <div className="liquid-card p-6 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <i className="bi bi-plugin text-brand-400"></i> VS Code Extensions (Cline / Roo Code)
                  </h3>
                  <p className="text-xs text-white/60">Thêm cấu hình vào file cài đặt MCP của extension Cline hoặc Roo Code.</p>
                </div>
                <span className="text-[10px] font-mono bg-white/10 px-2.5 py-1 rounded-md text-white/70">cline_mcp_settings.json</span>
              </div>

              <DownloadPrereq label="Tải file script vào máy:" zeroDepText="Không cần cài thư viện qua pip. Chạy trực tiếp bằng Python 3." />

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-bold text-white/80">Cấu hình JSON:</p>
                  <button onClick={() => copyText(getClineConfig(), 'cline-btn')} id="cline-btn" className="text-xs font-bold text-brand-400 hover:text-brand-300 flex items-center gap-1">
                    {copyLabel('cline-btn', 'bi-clipboard', 'Sao chép JSON')}
                  </button>
                </div>
                <pre className="bg-[var(--sc-ink-deep)] p-4 rounded-2xl border border-white/10 font-mono text-xs text-brand-300 overflow-x-auto select-all"><code>{getClineConfig()}</code></pre>
              </div>
            </div>
          </div>
        )}

        {/* Tab 6: ChatGPT Actions */}
        {activePlatform === 'chatgpt' && (
          <div className="space-y-6">
            <div className="liquid-card p-6 md:p-8 space-y-6 rounded-3xl border border-white/10 bg-[var(--sc-panel)]/80">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
                <div>
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <i className="bi bi-chat-dots-fill text-brand-400"></i> ChatGPT (Custom GPT / Actions)
                  </h3>
                  <p className="text-xs text-white/60">Tạo Custom GPT trên OpenAI ChatGPT Plus/Enterprise kết nối thẳng với ShieldCall API.</p>
                </div>
                <span className="text-[11px] font-mono bg-brand-400/10 text-brand-300 border border-brand-400/20 px-3 py-1 rounded-full w-fit">OpenAPI 3.1 Schema</span>
              </div>

              <div className="space-y-3">
                <p className="text-xs font-bold text-white uppercase tracking-wider">Quy trình 6 bước thiết lập Custom GPT:</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-white/80">
                  <div className="flex items-start gap-3 p-3.5 rounded-2xl bg-white/[0.02] border border-white/10">
                    <span className="w-6 h-6 rounded-full bg-brand-400/15 text-brand-300 flex items-center justify-center font-bold text-xs shrink-0 mt-0.5">1</span>
                    <div>
                      <p className="font-bold text-white">Khởi tạo GPT</p>
                      <p className="text-[11px] text-white/60">Truy cập <strong>ChatGPT → Explore GPTs → Create</strong>.</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 p-3.5 rounded-2xl bg-white/[0.02] border border-white/10">
                    <span className="w-6 h-6 rounded-full bg-brand-400/15 text-brand-300 flex items-center justify-center font-bold text-xs shrink-0 mt-0.5">2</span>
                    <div>
                      <p className="font-bold text-white">Đặt tên trợ lý</p>
                      <p className="text-[11px] text-white/60">Tại tab <strong>Configure</strong>, đặt tên <em>"ShieldCall VN - Trợ Lý An Toàn Số"</em>.</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 p-3.5 rounded-2xl bg-white/[0.02] border border-white/10">
                    <span className="w-6 h-6 rounded-full bg-brand-400/15 text-brand-300 flex items-center justify-center font-bold text-xs shrink-0 mt-0.5">3</span>
                    <div>
                      <p className="font-bold text-white">Cấu hình Instructions</p>
                      <p className="text-[11px] text-white/60">Dán <strong>Mẫu Prompt 1 (ShieldCall Cyber Sentry)</strong> bên dưới vào ô <strong>Instructions</strong>.</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 p-3.5 rounded-2xl bg-white/[0.02] border border-white/10">
                    <span className="w-6 h-6 rounded-full bg-brand-400/15 text-brand-300 flex items-center justify-center font-bold text-xs shrink-0 mt-0.5">4</span>
                    <div>
                      <p className="font-bold text-white">Thêm Action mới</p>
                      <p className="text-[11px] text-white/60">Cuộn xuống mục <strong>Actions → Create new action</strong>.</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 p-3.5 rounded-2xl bg-white/[0.02] border border-white/10">
                    <span className="w-6 h-6 rounded-full bg-brand-400/15 text-brand-300 flex items-center justify-center font-bold text-xs shrink-0 mt-0.5">5</span>
                    <div>
                      <p className="font-bold text-white">Xác thực API Key</p>
                      <p className="text-[11px] text-white/60">Chọn Auth type là <strong>API Key</strong> (Auth Type: <code>Custom</code>, Header Name: <code>X-API-Key</code>).</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 p-3.5 rounded-2xl bg-white/[0.02] border border-white/10">
                    <span className="w-6 h-6 rounded-full bg-brand-400/15 text-brand-300 flex items-center justify-center font-bold text-xs shrink-0 mt-0.5">6</span>
                    <div>
                      <p className="font-bold text-white">Nhúng Schema</p>
                      <p className="text-[11px] text-white/60">Dán toàn bộ lược đồ OpenAPI Schema bên dưới vào ô <strong>Schema</strong>.</p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="space-y-2.5">
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-brand-400"></span>
                    <p className="text-xs font-bold text-white uppercase tracking-wider">Lược đồ OpenAPI 3.1 Chuẩn Hóa:</p>
                  </div>
                  <button onClick={() => copyText(getChatGPTSchema(), 'chatgpt-btn')} id="chatgpt-btn" className="px-4 py-2 rounded-xl text-xs font-bold bg-brand-400/10 hover:bg-brand-400/20 text-brand-300 border border-brand-400/30 flex items-center gap-1.5 transition-all cursor-pointer">
                    {copyLabel('chatgpt-btn', 'bi-clipboard', 'Sao chép OpenAPI Schema')}
                  </button>
                </div>
                <pre className="bg-[var(--sc-gray-950)] p-4 rounded-2xl border border-white/15 font-mono text-xs text-brand-300 overflow-x-auto select-all max-h-[380px] leading-relaxed"><code>{getChatGPTSchema()}</code></pre>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Ready-to-Copy Starter Prompts Section */}
      <div id="starter-prompts" className="space-y-6 pt-6">
        <div className="border-b border-white/10 pb-4">
          <h2 className="text-2xl font-black text-white tracking-tight">Mẫu System Prompt Khởi Đầu (Ready to Copy)</h2>
          <p className="text-xs text-white/60">
            Sao chép các mẫu prompt này dán vào <strong>System Prompt</strong> (Claude Projects, Cursor Rules, Custom GPT Instructions) để biến chatbot thành trợ lý chuyên sâu.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {PROMPT_CARDS.map((p) => (
            <div key={p.id} className={`liquid-card p-6 space-y-4 flex flex-col justify-between ${p.cardCls}`}>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className={`px-2.5 py-0.5 rounded-full ${p.badgeCls} text-[10px] font-black uppercase tracking-wider`}>
                    {p.badge}
                  </span>
                  <i className={`bi ${p.icon}`}></i>
                </div>
                <h3 className="text-base font-black text-white">{p.title}</h3>
                <p className="text-xs text-white/60">{p.desc}</p>
                <div className="bg-black/50 p-3 rounded-xl border border-white/10 text-xs font-mono text-white/70 max-h-48 overflow-y-auto whitespace-pre-wrap select-all">{p.text}</div>
              </div>
              <button onClick={() => copyText(p.text, p.id)} id={p.id} className={`w-full liquid-btn py-2.5 px-4 text-xs font-black ${p.btnCls} uppercase tracking-wider`}>
                {copiedId === p.id ? <><i className="bi bi-check2 mr-1"></i> Đã sao chép!</> : <><i className="bi bi-clipboard mr-1"></i> {p.btnText}</>}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Tools & Parameter Reference Table */}
      <div id="tools-reference" className="space-y-6 pt-6">
        <div className="border-b border-white/10 pb-4">
          <h2 className="text-2xl font-black text-white tracking-tight">Danh Mục Công Cụ MCP (Tools Reference)</h2>
          <p className="text-xs text-white/60">Mọi công cụ mà ShieldCall MCP Server tự động cung cấp cho Chatbot của bạn.</p>
        </div>

        <div className="overflow-x-auto rounded-2xl border border-white/10">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-white/5 text-white/55 uppercase tracking-wider border-b border-white/10 text-[10px]">
              <tr>
                <th className="p-4">Tên Tool</th>
                <th className="p-4">Tham Số Đầu Vào</th>
                <th className="p-4">Mục Đích Sử Dụng</th>
                <th className="p-4">Dữ Liệu Trả Về</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 font-mono text-white/80">
              {TOOLS_TABLE.map((t) => (
                <tr key={t.name} className="hover:bg-white/[0.02]">
                  <td className="p-4 font-bold text-brand-400">{t.name}</td>
                  <td className="p-4 text-white/60">
                    {t.params.length === 0 ? (
                      <em>(không tham số)</em>
                    ) : (
                      t.params.map((param, i) => (
                        <span key={param}>
                          {i > 0 && <br />}
                          <code>{param}</code>
                        </span>
                      ))
                    )}
                  </td>
                  <td className="p-4 font-sans text-white/80">{t.use}</td>
                  <td className="p-4 text-[11px] text-white/60"><code>{t.returns}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Live Tool Playground Section */}
      <div id="live-playground" className="space-y-6 pt-6">
        <div className="border-b border-white/10 pb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-brand-400/10 text-brand-300 text-[10px] font-black uppercase tracking-wider mb-2 border border-brand-400/20">
              <i className="bi bi-broadcast"></i> Tương tác trực tiếp • 10 MCP Tools
            </div>
            <h2 className="text-2xl font-black text-white tracking-tight">Thử Nghiệm Trực Tiếp Công Cụ MCP (Live Playground)</h2>
            <p className="text-xs text-white/60">Thử nghiệm phản hồi thực tế của các API an ninh số ngay trên giao diện web trước khi cấu hình vào Chatbot.</p>
          </div>
          <div className="flex items-center gap-2 text-xs flex-wrap">
            {user ? (
              <>
                <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-safe-500/10 border border-safe-500/30 text-safe-400 font-bold">
                  <span className="w-2 h-2 rounded-full bg-safe-400 animate-pulse"></span>
                  Phiên Web Xác Thực (Session Auth)
                </span>
                {activeKeys.length > 0 && (
                  <span className="font-mono text-brand-300 bg-black/60 px-2.5 py-1.5 rounded-xl border border-white/10 text-[11px]">
                    {'Mã khóa: ' + (getCurrentApiKey().startsWith('sc_live_') ? getCurrentApiKey().substring(0, 16) + '...' : 'sc_live_...')}
                  </span>
                )}
              </>
            ) : (
              <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-brand-500/10 border border-brand-500/30 text-brand-300 font-bold">
                <span className="w-2 h-2 rounded-full bg-brand-400"></span>
                Live Web Sandbox (Bypass Demo)
              </span>
            )}
          </div>
        </div>

        <div className="liquid-card p-6 border-brand-500/20 bg-gradient-to-b from-brand-500/[0.04] to-transparent space-y-6">
          {/* Tool Selection & Presets */}
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <label className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <i className="bi bi-tools text-brand-400"></i> Chọn công cụ cần thử nghiệm:
              </label>
              <div className="flex items-center gap-2 flex-wrap text-xs">
                <span className="text-white/55 text-[11px]">Mẫu dữ liệu nhanh:</span>
                <button onClick={() => setPreset('sms_otp')} className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/15 text-brand-300 border border-white/10 text-[11px] transition-all cursor-pointer">
                  SMS đòi OTP
                </button>
                <button onClick={() => setPreset('bank_scam')} className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/15 text-brand-300 border border-white/10 text-[11px] transition-all cursor-pointer">
                  STK ngân hàng
                </button>
                <button onClick={() => setPreset('phishing_link')} className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/15 text-brand-300 border border-white/10 text-[11px] transition-all cursor-pointer">
                  Link DVC giả
                </button>
                <button onClick={() => setPreset('fake_email')} className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/15 text-brand-300 border border-white/10 text-[11px] transition-all cursor-pointer">
                  Email lừa đảo
                </button>
                <button onClick={() => setPreset('full_incident')} className="px-2.5 py-1 rounded-lg bg-brand-500/15 hover:bg-brand-500/25 text-brand-200 border border-brand-400/30 text-[11px] transition-all cursor-pointer font-bold">
                  Vụ việc đa nguồn
                </button>
                <button onClick={() => setPreset('db_lookup')} className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/15 text-brand-300 border border-white/10 text-[11px] transition-all cursor-pointer">
                  Tra cứu kho đen
                </button>
                <button onClick={() => setPreset('radar_trends')} className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/15 text-brand-300 border border-white/10 text-[11px] transition-all cursor-pointer">
                  Xu hướng radar
                </button>
              </div>
            </div>

            {/* 10 MCP Tools Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
              {PLAYGROUND_TOOLS.map((t) => {
                const active = playgroundTool === t.tool;
                return (
                  <button
                    key={t.tool}
                    onClick={() => selectTool(t.tool)}
                    className={`p-3 rounded-2xl text-left border transition-all cursor-pointer group flex flex-col justify-between ${
                      active
                        ? 'bg-brand-400 text-black font-black shadow-lg shadow-brand-400/25 border-brand-300 ring-2 ring-brand-400/40'
                        : 'bg-white/5 text-white/80 hover:bg-white/10 border-white/10 hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1 mb-1.5">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <i className={`bi ${t.icon} text-xs shrink-0 ${active ? 'text-black' : 'text-brand-400'}`}></i>
                        <span className="font-mono text-xs font-bold truncate">{t.tool}</span>
                      </div>
                      <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold uppercase shrink-0 ${active ? 'bg-black/20 text-black' : t.badge}`}>
                        {['lookup_scam_db', 'get_scam_radar_trends', 'get_supported_banks'].includes(t.tool) ? 'GET' : 'POST'}
                      </span>
                    </div>
                    <p className={`text-[11px] leading-tight ${active ? 'text-black/80' : 'text-white/60'}`}>{t.desc}</p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Scoped Layout Safeguard (prevents grid collapse under any browser cache) */}
          <style>{`
                .mcp-grid-container {
                    display: flex;
                    flex-direction: column;
                    gap: 1.5rem;
                    width: 100%;
                    min-width: 0;
                }
                @media (min-width: 1024px) {
                    .mcp-grid-container {
                        display: grid !important;
                        grid-template-columns: repeat(12, minmax(0, 1fr)) !important;
                        gap: 1.5rem !important;
                        align-items: start !important;
                    }
                    .mcp-col-5 {
                        grid-column: span 5 / span 5 !important;
                        width: 100% !important;
                        min-width: 0 !important;
                    }
                    .mcp-col-7 {
                        grid-column: span 7 / span 7 !important;
                        width: 100% !important;
                        min-width: 0 !important;
                    }
                }
            `}</style>

          {/* Input Form & Output Console Section */}
          <div className="mcp-grid-container grid grid-cols-1 lg:grid-cols-12 gap-6 items-start w-full min-w-0">
            {/* Left Panel: Input Parameters */}
            <div className="mcp-col-5 lg:col-span-5 w-full space-y-4 bg-[var(--sc-panel)] border border-white/10 p-5 rounded-2xl shadow-xl">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <span className="text-xs font-black text-white uppercase tracking-wider flex items-center gap-2">
                  <i className="bi bi-sliders text-brand-400"></i> Tham Số Đầu Vào
                </span>
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-bold font-mono px-1.5 py-0.5 rounded bg-white/10 text-white/70 uppercase">
                    {isGetTool ? 'GET' : 'POST'}
                  </span>
                  <span className="font-mono text-[11px] text-brand-300 bg-brand-500/10 px-2 py-0.5 rounded border border-brand-500/20">{playgroundTool}</span>
                </div>
              </div>

              {/* Optional Custom API Key accordion */}
              <div className="border border-white/10 rounded-xl p-2.5 bg-white/[0.02]">
                <button onClick={() => setShowKeyInput((v) => !v)} type="button" className="w-full flex items-center justify-between text-[11px] text-white/60 hover:text-white transition-all cursor-pointer font-sans">
                  <span className="flex items-center gap-1.5"><i className="bi bi-key text-brand-400"></i> Tùy chọn: Nhập API Key kiểm thử</span>
                  <i className={`bi ${showKeyInput ? 'bi-chevron-up' : 'bi-chevron-down'}`}></i>
                </button>
                {showKeyInput && (
                  <div className="pt-2 space-y-1.5">
                    <input
                      type="text"
                      value={playgroundCustomKey}
                      onChange={(e) => setPlaygroundCustomKey(e.target.value)}
                      placeholder="sc_live_xxxxxxxxxxxxxxxxxxxxxxxx..."
                      className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-lg px-3 py-2 text-[11px] font-mono text-brand-300 placeholder-white/30 focus:outline-none focus:border-brand-400"
                    />
                    <p className="text-[10px] text-white/55">Để trống để sử dụng phiên đăng nhập web hoặc sandbox mặc định.</p>
                  </div>
                )}
              </div>

              {/* check_phone inputs */}
              {playgroundTool === 'check_phone' && (
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-bold text-white/80">Số điện thoại cần quét:</label>
                    <div className="flex items-center gap-1 text-[10px]">
                      <span className="text-white/55">Gợi ý:</span>
                      <button type="button" onClick={() => setPlaygroundPhone('0912345678')} className="text-brand-400 hover:underline">0912345678</button>
                      <span className="text-white/35">|</span>
                      <button type="button" onClick={() => setPlaygroundPhone('+84988776655')} className="text-brand-400 hover:underline">+84988776655</button>
                    </div>
                  </div>
                  <div className="relative">
                    <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-white/55 text-xs"><i className="bi bi-telephone"></i></span>
                    <input
                      type="text"
                      value={playgroundPhone}
                      onChange={(e) => setPlaygroundPhone(e.target.value)}
                      onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void runPlayground(); } }}
                      placeholder="Ví dụ: 0912345678 hoặc +84988776655"
                      className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl pl-9 pr-4 py-2.5 text-xs font-mono text-brand-300 placeholder-white/30 focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/30 transition-all"
                    />
                  </div>
                  <p className="text-[11px] text-white/60 leading-relaxed">Hệ thống tra cứu nhà mạng, dấu hiệu số ảo VoIP và danh sách đen viễn thông.</p>
                </div>
              )}

              {/* check_bank_account inputs */}
              {playgroundTool === 'check_bank_account' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-bold text-white/80">Thông tin tài khoản:</label>
                    <div className="flex items-center gap-1 text-[10px]">
                      <span className="text-white/55">Gợi ý:</span>
                      <button type="button" onClick={() => { setPlaygroundBank('MB'); setPlaygroundAccount('0987654321'); }} className="text-brand-400 hover:underline">MB 0987654321</button>
                      <span className="text-white/35">|</span>
                      <button type="button" onClick={() => { setPlaygroundBank('VCB'); setPlaygroundAccount('1012345678'); }} className="text-brand-400 hover:underline">VCB</button>
                    </div>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                    <div className="space-y-1">
                      <label className="text-[11px] font-bold text-white/70">Ngân hàng:</label>
                      <input
                        type="text"
                        value={playgroundBank}
                        onChange={(e) => setPlaygroundBank(e.target.value)}
                        onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void runPlayground(); } }}
                        placeholder="MB, VCB, ACB..."
                        list="mcp-bank-suggestions"
                        className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl px-3 py-2 text-xs font-mono text-brand-300 placeholder-white/30 focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/30 transition-all"
                      />
                      <datalist id="mcp-bank-suggestions">
                        {BANK_SUGGESTIONS.map((b) => (
                          <option key={b.value} value={b.value}>{b.label}</option>
                        ))}
                      </datalist>
                    </div>
                    <div className="space-y-1">
                      <label className="text-[11px] font-bold text-white/70">Số tài khoản:</label>
                      <input
                        type="text"
                        value={playgroundAccount}
                        onChange={(e) => setPlaygroundAccount(e.target.value)}
                        onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void runPlayground(); } }}
                        placeholder="0987654321"
                        className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl px-3 py-2 text-xs font-mono text-brand-300 placeholder-white/30 focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/30 transition-all"
                      />
                    </div>
                  </div>
                  <p className="text-[11px] text-white/60 leading-relaxed">Đối soát tài khoản trong danh sách đen tài chính và các vụ án lừa đảo đã ghi nhận.</p>
                </div>
              )}

              {/* check_url_or_domain inputs */}
              {playgroundTool === 'check_url_or_domain' && (
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-bold text-white/80">Đường link hoặc tên miền (URL):</label>
                    <div className="flex items-center gap-1 text-[10px]">
                      <span className="text-white/55">Gợi ý:</span>
                      <button type="button" onClick={() => setPlaygroundUrl('http://dichvucong-vn.top/login')} className="text-brand-400 hover:underline">dichvucong-vn.top</button>
                    </div>
                  </div>
                  <div className="relative">
                    <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-white/55 text-xs"><i className="bi bi-globe"></i></span>
                    <input
                      type="text"
                      value={playgroundUrl}
                      onChange={(e) => setPlaygroundUrl(e.target.value)}
                      onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void runPlayground(); } }}
                      placeholder="Ví dụ: http://dichvucong-vn.top/login"
                      className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl pl-9 pr-4 py-2.5 text-xs font-mono text-brand-300 placeholder-white/30 focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/30 transition-all"
                    />
                  </div>
                  <p className="text-[11px] text-white/60 leading-relaxed">Phân tích SSL, khoảng cách Levenshtein nhận diện tên miền nhái thương hiệu.</p>
                </div>
              )}

              {/* analyze_message inputs */}
              {playgroundTool === 'analyze_message' && (
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-bold text-white/80">Nội dung tin nhắn / SMS:</label>
                    <div className="flex items-center gap-1 text-[10px]">
                      <button type="button" onClick={() => setPreset('sms_otp')} className="text-brand-400 hover:underline">Điền mẫu OTP</button>
                    </div>
                  </div>
                  <textarea
                    value={playgroundMessage}
                    onChange={(e) => setPlaygroundMessage(e.target.value)}
                    rows={4}
                    placeholder="Dán nội dung tin nhắn đáng ngờ vào đây..."
                    className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl p-3 text-xs font-mono text-brand-300 placeholder-white/30 focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/30 transition-all"
                  ></textarea>
                  <p className="text-[11px] text-white/60 leading-relaxed">Phân tích bẫy thao túng tâm lý, mạo danh công an, đe dọa hoặc giục giã nạp tiền.</p>
                </div>
              )}

              {/* check_email_sender inputs */}
              {playgroundTool === 'check_email_sender' && (
                <div className="space-y-3">
                  <div className="space-y-1.5">
                    <label className="text-xs font-bold text-white/80">Địa chỉ email người gửi:</label>
                    <div className="relative">
                      <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-white/55 text-xs"><i className="bi bi-envelope-at"></i></span>
                      <input
                        type="text"
                        value={playgroundEmail}
                        onChange={(e) => setPlaygroundEmail(e.target.value)}
                        onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void runPlayground(); } }}
                        placeholder="Ví dụ: fraud@phishing-fake-bank.top"
                        className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl pl-9 pr-4 py-2.5 text-xs font-mono text-brand-300 placeholder-white/30 focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/30 transition-all"
                      />
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-bold text-white/80">Nội dung thư điện tử (tùy chọn):</label>
                    <textarea
                      value={playgroundMessage}
                      onChange={(e) => setPlaygroundMessage(e.target.value)}
                      rows={2}
                      placeholder="Nội dung thư..."
                      className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl p-3 text-xs font-mono text-brand-300 placeholder-white/30 focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/30 transition-all"
                    ></textarea>
                  </div>
                </div>
              )}

              {/* scan_full_incident inputs */}
              {playgroundTool === 'scan_full_incident' && (
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-bold text-brand-300">Quét tổng hợp đa nguồn:</span>
                    <button type="button" onClick={() => setPreset('full_incident')} className="text-[10px] text-brand-400 hover:underline">Điền mẫu vụ việc</button>
                  </div>
                  <div className="space-y-1">
                    <label className="text-[11px] font-bold text-white/70">Số điện thoại:</label>
                    <input
                      type="text"
                      value={playgroundPhone}
                      onChange={(e) => setPlaygroundPhone(e.target.value)}
                      onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void runPlayground(); } }}
                      placeholder="0912345678"
                      className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl px-3 py-2 text-xs font-mono text-brand-300 focus:outline-none focus:border-brand-400"
                    />
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <div className="space-y-1">
                      <label className="text-[11px] font-bold text-white/70">Ngân hàng:</label>
                      <input
                        type="text"
                        value={playgroundBank}
                        onChange={(e) => setPlaygroundBank(e.target.value)}
                        onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void runPlayground(); } }}
                        placeholder="MB"
                        className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl px-3 py-2 text-xs font-mono text-brand-300 focus:outline-none focus:border-brand-400"
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="text-[11px] font-bold text-white/70">Số tài khoản:</label>
                      <input
                        type="text"
                        value={playgroundAccount}
                        onChange={(e) => setPlaygroundAccount(e.target.value)}
                        onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void runPlayground(); } }}
                        placeholder="0987654321"
                        className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl px-3 py-2 text-xs font-mono text-brand-300 focus:outline-none focus:border-brand-400"
                      />
                    </div>
                  </div>
                  <div className="space-y-1">
                    <label className="text-[11px] font-bold text-white/70">Đường link / URL:</label>
                    <input
                      type="text"
                      value={playgroundUrl}
                      onChange={(e) => setPlaygroundUrl(e.target.value)}
                      onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void runPlayground(); } }}
                      placeholder="http://dichvucong-vn.top"
                      className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl px-3 py-2 text-xs font-mono text-brand-300 focus:outline-none focus:border-brand-400"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-[11px] font-bold text-white/70">Nội dung tin nhắn / kịch bản:</label>
                    <textarea
                      value={playgroundMessage}
                      onChange={(e) => setPlaygroundMessage(e.target.value)}
                      rows={2}
                      placeholder="Kịch bản kẻ lừa đảo nói..."
                      className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl p-2.5 text-xs font-mono text-brand-300 focus:outline-none focus:border-brand-400"
                    ></textarea>
                  </div>
                </div>
              )}

              {/* lookup_scam_db inputs */}
              {playgroundTool === 'lookup_scam_db' && (
                <div className="space-y-3">
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <label className="text-xs font-bold text-white/80">Từ khóa hoặc chỉ số tra cứu:</label>
                      <div className="flex items-center gap-1 text-[10px]">
                        <button type="button" onClick={() => setPlaygroundQuery('0912345678')} className="text-brand-400 hover:underline">0912345678</button>
                        <span className="text-white/35">|</span>
                        <button type="button" onClick={() => setPlaygroundQuery('MBBank')} className="text-brand-400 hover:underline">MBBank</button>
                      </div>
                    </div>
                    <div className="relative">
                      <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-white/55 text-xs"><i className="bi bi-search"></i></span>
                      <input
                        type="text"
                        value={playgroundQuery}
                        onChange={(e) => setPlaygroundQuery(e.target.value)}
                        onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void runPlayground(); } }}
                        placeholder="Ví dụ: 0912345678, MBBank, dịch vụ công..."
                        className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl pl-9 pr-4 py-2.5 text-xs font-mono text-brand-300 placeholder-white/30 focus:outline-none focus:border-brand-400"
                      />
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-bold text-white/80">Lọc theo loại thực thể:</label>
                    <select
                      value={playgroundEntityType}
                      onChange={(e) => setPlaygroundEntityType(e.target.value)}
                      className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl px-3 py-2 text-xs font-mono text-brand-300 focus:outline-none focus:border-brand-400"
                    >
                      <option value="all">Tất cả danh mục (all)</option>
                      <option value="phone">Số điện thoại (phone)</option>
                      <option value="account">Tài khoản ngân hàng (account)</option>
                      <option value="domain">Tên miền website (domain)</option>
                      <option value="email">Hộp thư điện tử (email)</option>
                    </select>
                  </div>
                </div>
              )}

              {/* get_scam_radar_trends info */}
              {playgroundTool === 'get_scam_radar_trends' && (
                <div className="p-4 rounded-xl bg-brand-500/[0.04] border border-brand-500/20 text-xs text-white/70 space-y-2">
                  <p className="font-bold text-white flex items-center gap-1.5"><i className="bi bi-radar text-brand-400"></i> Công cụ truy vấn thống kê thời gian thực</p>
                  <p className="leading-relaxed">Không cần tham số đầu vào. Hệ thống sẽ truy xuất số lượng vụ việc trong tuần, biến động tỷ lệ phần trăm, các số điện thoại và tên miền phishing đang nóng nhất.</p>
                  <div className="pt-1 flex items-center gap-2 text-[11px] text-brand-300">
                    <span className="w-2 h-2 rounded-full bg-safe-400 animate-pulse"></span>
                    <span>Sẵn sàng truy xuất dữ liệu radar</span>
                  </div>
                </div>
              )}

              {/* get_supported_banks info */}
              {playgroundTool === 'get_supported_banks' && (
                <div className="p-4 rounded-xl bg-brand-500/[0.04] border border-brand-500/20 text-xs text-white/70 space-y-2">
                  <p className="font-bold text-white flex items-center gap-1.5"><i className="bi bi-bank text-brand-400"></i> Danh mục thành viên VietQR</p>
                  <p className="leading-relaxed">Không cần tham số đầu vào. Hệ thống sẽ truy vấn danh mục 65+ ngân hàng tại Việt Nam kèm mã BIN chuẩn và tên viết tắt.</p>
                  <div className="pt-1 flex items-center gap-2 text-[11px] text-brand-300">
                    <span className="w-2 h-2 rounded-full bg-safe-400 animate-pulse"></span>
                    <span>Sẵn sàng tải danh mục ngân hàng</span>
                  </div>
                </div>
              )}

              {/* report_scam inputs */}
              {playgroundTool === 'report_scam' && (
                <div className="space-y-2.5">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <div className="space-y-1">
                      <label className="text-[11px] font-bold text-white/70">Loại mục tiêu:</label>
                      <select
                        value={playgroundReportTargetType}
                        onChange={(e) => setPlaygroundReportTargetType(e.target.value)}
                        className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl px-2.5 py-2 text-xs font-mono text-brand-300"
                      >
                        <option value="phone">phone (Số điện thoại)</option>
                        <option value="account">account (STK ngân hàng)</option>
                        <option value="domain">domain (Tên miền / URL)</option>
                        <option value="other">other (Khác)</option>
                      </select>
                    </div>
                    <div className="space-y-1">
                      <label className="text-[11px] font-bold text-white/70">Hình thức lừa đảo:</label>
                      <select
                        value={playgroundReportScamType}
                        onChange={(e) => setPlaygroundReportScamType(e.target.value)}
                        className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl px-2.5 py-2 text-xs font-mono text-brand-300"
                      >
                        <option value="phishing">phishing</option>
                        <option value="police_impersonation">police_impersonation</option>
                        <option value="bank_impersonation">bank_impersonation</option>
                        <option value="otp_steal">otp_steal</option>
                        <option value="recruitment_scam">recruitment_scam</option>
                        <option value="investment_scam">investment_scam</option>
                        <option value="other">other</option>
                      </select>
                    </div>
                  </div>
                  <div className="space-y-1">
                    <label className="text-[11px] font-bold text-white/70">Giá trị mục tiêu:</label>
                    <input
                      type="text"
                      value={playgroundReportTargetValue}
                      onChange={(e) => setPlaygroundReportTargetValue(e.target.value)}
                      onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void runPlayground(); } }}
                      placeholder="0988776655 hoặc URL..."
                      className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl px-3 py-2 text-xs font-mono text-brand-300"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-[11px] font-bold text-white/70">Mô tả vụ việc:</label>
                    <textarea
                      value={playgroundReportDescription}
                      onChange={(e) => setPlaygroundReportDescription(e.target.value)}
                      rows={2}
                      placeholder="Chi tiết thủ đoạn..."
                      className="w-full bg-[var(--sc-gray-950)] border border-white/15 rounded-xl p-2.5 text-xs font-mono text-brand-300"
                    ></textarea>
                  </div>
                </div>
              )}

              {/* Run Playground Button */}
              <div className="pt-1 space-y-1.5">
                <button
                  onClick={() => void runPlayground()}
                  disabled={playgroundLoading}
                  className="w-full py-3 px-6 rounded-xl bg-brand-400 hover:bg-brand-300 text-black font-black text-xs uppercase tracking-wider flex items-center justify-center gap-2 shadow-lg shadow-brand-400/25 transition-all cursor-pointer select-none active:scale-[0.99] disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {playgroundLoading ? (
                    <span className="inline-flex items-center gap-2"><i className="bi bi-arrow-repeat animate-spin text-sm"></i> Đang thực thi phân tích...</span>
                  ) : (
                    <span className="inline-flex items-center gap-2">
                      <i className="bi bi-play-fill text-base"></i>
                      <span>Chạy Thử Nghiệm:</span>
                      <span className="font-mono bg-black/15 px-1.5 py-0.5 rounded text-[11px]">{playgroundTool}</span>
                    </span>
                  )}
                </button>
                <p className="text-[10px] text-center text-white/55">Nhấn Enter trong ô nhập liệu để chạy nhanh</p>
              </div>
            </div>

            {/* Right Panel: High-contrast Developer Console */}
            <div id="playground-console" className="mcp-col-7 lg:col-span-7 w-full space-y-3 min-w-0 flex flex-col">
              {/* Console Header & Tab Switcher */}
              <div className="bg-black/60 border border-white/10 rounded-2xl p-3 flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <span
                    className={`w-2.5 h-2.5 rounded-full ${
                      playgroundLoading
                        ? 'bg-warn-400 animate-ping'
                        : playgroundResult && !playgroundError
                          ? 'bg-safe-400'
                          : playgroundError
                            ? 'bg-danger-500'
                            : 'bg-white/20'
                    }`}
                  ></span>
                  <span className="text-xs font-bold text-white/90">Console MCP Server</span>
                  {!!playgroundHttpStatus && (
                    <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-white/10 text-white/70">{'HTTP ' + playgroundHttpStatus}</span>
                  )}
                  {playgroundLatency > 0 && (
                    <span className="font-mono text-[10px] text-brand-300 bg-brand-500/10 px-2 py-0.5 rounded border border-brand-500/20">{playgroundLatency + ' ms'}</span>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  {/* View Tab Switcher */}
                  <div className="flex items-center bg-white/5 rounded-lg p-0.5 border border-white/10 text-xs">
                    <button
                      onClick={() => setPlaygroundTab('visual')}
                      className={`px-2.5 py-1 rounded-md transition-all cursor-pointer flex items-center gap-1.5 text-[11px] ${
                        playgroundTab === 'visual' ? 'bg-brand-400 text-black font-black' : 'text-white/60 hover:text-white'
                      }`}
                    >
                      <i className="bi bi-eye-fill"></i> Trực Quan
                    </button>
                    <button
                      onClick={() => setPlaygroundTab('json')}
                      className={`px-2.5 py-1 rounded-md transition-all cursor-pointer flex items-center gap-1.5 text-[11px] ${
                        playgroundTab === 'json' ? 'bg-brand-400 text-black font-black' : 'text-white/60 hover:text-white'
                      }`}
                    >
                      <i className="bi bi-code-slash"></i> JSON Chi Tiết
                    </button>
                  </div>

                  {/* Copy JSON button */}
                  {playgroundResult !== null && !playgroundLoading && (
                    <button
                      onClick={() => copyText(JSON.stringify(playgroundResult, null, 2), 'pg-copy-btn')}
                      id="pg-copy-btn"
                      className="text-[11px] font-bold text-brand-300 hover:text-brand-200 bg-brand-500/10 hover:bg-brand-500/20 border border-brand-500/20 px-2.5 py-1 rounded-lg flex items-center gap-1 cursor-pointer transition-all"
                    >
                      {copiedId === 'pg-copy-btn' ? <><i className="bi bi-check2"></i> Đã sao chép!</> : <><i className="bi bi-clipboard"></i> Chép JSON</>}
                    </button>
                  )}
                </div>
              </div>

              {/* Console Body Container */}
              <div className="relative bg-[var(--sc-slate-950)] rounded-2xl border border-white/15 p-5 min-h-[460px] max-h-[620px] overflow-y-auto font-sans">
                {/* State 1: Initial Empty State */}
                {playgroundResult === null && !playgroundLoading && !playgroundError && (
                  <div className="h-full min-h-[400px] flex flex-col items-center justify-center text-center text-white/55 space-y-4 py-16">
                    <div className="w-16 h-16 rounded-3xl bg-brand-500/5 border border-brand-500/20 flex items-center justify-center text-brand-400 text-3xl shadow-inner">
                      <i className="bi bi-terminal-split"></i>
                    </div>
                    <div className="max-w-md space-y-1">
                      <p className="text-sm font-bold text-white/80">Sẵn Sàng Tiếp Nhận Lệnh Thử Nghiệm</p>
                      <p className="text-xs text-white/60 leading-relaxed">Chọn một công cụ bên trên hoặc nhấn nhanh vào các "Mẫu dữ liệu nhanh" rồi nhấn "Chạy Thử Nghiệm" để xem kết quả phân tích thời gian thực.</p>
                    </div>
                  </div>
                )}

                {/* State 2: Loading State */}
                {playgroundLoading && (
                  <div className="h-full min-h-[400px] flex flex-col items-center justify-center text-center text-brand-300 space-y-4 py-16">
                    <div className="relative w-14 h-14">
                      <div className="w-14 h-14 border-2 border-brand-400/20 border-t-brand-400 rounded-full animate-spin"></div>
                      <div className="absolute inset-0 flex items-center justify-center text-brand-400 text-lg">
                        <i className="bi bi-shield"></i>
                      </div>
                    </div>
                    <div className="space-y-1">
                      <p className="text-sm font-bold text-white">Đang Truy Vấn Hạ Tầng An Ninh ShieldCall</p>
                      <p className="text-xs text-white/60">Đang phân tích chỉ số rủi ro, danh sách đen viễn thông và cơ sở dữ liệu gian lận...</p>
                    </div>
                  </div>
                )}

                {/* State 3: Execution Error */}
                {playgroundError && !playgroundLoading && (
                  <div className="p-5 rounded-2xl bg-danger-950/40 border border-danger-500/30 text-danger-200 text-xs space-y-3">
                    <div className="flex items-center gap-2 text-danger-400 font-bold text-sm">
                      <i className="bi bi-exclamation-octagon-fill text-base"></i> Lỗi thực thi công cụ
                    </div>
                    <div className="bg-black/60 p-3.5 rounded-xl font-mono text-[11px] text-danger-300 border border-danger-500/20 break-words">{playgroundError}</div>
                    <div className="text-[11px] text-white/60 space-y-1">
                      <p className="font-bold text-white/80">Gợi ý khắc phục:</p>
                      <p>• Kiểm tra lại định dạng tham số đầu vào của công cụ.</p>
                      <p>• Đảm bảo hệ thống backend đang hoạt động bình thường.</p>
                      <p>• Nếu dùng Custom API Key, hãy đảm bảo khóa có dạng <code className="text-brand-300">sc_live_...</code> và còn hạn ngạch.</p>
                    </div>
                  </div>
                )}

                {/* State 4: Successful Result */}
                {playgroundResult !== null && !playgroundLoading && (
                  <div>
                    {/* TAB 1: VISUAL ASSESSMENT */}
                    {playgroundTab === 'visual' && (
                      <div className="space-y-5">
                        {/* SPECIAL CASE 1: get_supported_banks */}
                        {playgroundTool === 'get_supported_banks' && resultIsArray && (
                          <div className="space-y-3">
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
                              <div className="flex items-center gap-2">
                                <span className="w-2.5 h-2.5 rounded-full bg-safe-400"></span>
                                <span className="text-xs font-bold text-white uppercase tracking-wider">Danh Sách Ngân Hàng VietQR</span>
                                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-brand-500/15 text-brand-300 font-bold">{bankTotal + ' thành viên'}</span>
                              </div>
                              <input
                                type="text"
                                value={bankSearchFilter}
                                onChange={(e) => setBankSearchFilter(e.target.value)}
                                placeholder="Tìm tên, mã, BIN..."
                                className="bg-black/50 border border-white/15 rounded-lg px-2.5 py-1 text-xs font-mono text-brand-300 placeholder-white/30 focus:outline-none focus:border-brand-400 w-full sm:w-44"
                              />
                            </div>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                              {filteredBanks.map((bank, idx) => (
                                <div key={str(bank.bin) || str(bank.code) || idx} className="p-3 rounded-xl bg-white/[0.02] border border-white/10 flex items-center justify-between gap-3 hover:bg-white/[0.04] transition-all">
                                  <div className="flex items-center gap-2.5 min-w-0">
                                    <div className="w-8 h-8 rounded-lg bg-white p-1 flex items-center justify-center shrink-0">
                                      <img
                                        src={str(bank.logo)}
                                        alt={str(bank.shortName)}
                                        className="max-h-full max-w-full object-contain"
                                        onError={(e) => { e.currentTarget.style.display = 'none'; }}
                                      />
                                    </div>
                                    <div className="min-w-0">
                                      <div className="flex items-center gap-1.5">
                                        <span className="font-bold text-white text-xs truncate">{str(bank.shortName) || str(bank.code)}</span>
                                        <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-brand-500/20 text-brand-300 font-bold">{str(bank.code)}</span>
                                      </div>
                                      <p className="text-[10px] text-white/60 truncate">{str(bank.name)}</p>
                                    </div>
                                  </div>
                                  <div className="text-right shrink-0">
                                    <span className="text-[10px] font-mono text-white/55 block">BIN</span>
                                    <span className="text-xs font-mono font-bold text-brand-300">{str(bank.bin)}</span>
                                  </div>
                                </div>
                              ))}
                            </div>
                            {filteredBanks.length === 0 && (
                              <p className="text-xs text-white/55 text-center py-6">Không tìm thấy ngân hàng nào khớp với từ khóa tìm kiếm.</p>
                            )}
                          </div>
                        )}

                        {/* SPECIAL CASE 2: get_scam_radar_trends */}
                        {playgroundTool === 'get_scam_radar_trends' && !resultIsArray && resultObj.reports_this_week !== undefined && (
                          <div className="space-y-4">
                            <div className="flex items-center justify-between border-b border-white/10 pb-2">
                              <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                                <i className="bi bi-radar text-brand-400"></i> Thống Kê Radar An Ninh Số
                              </span>
                              <span className="text-[10px] text-safe-400 font-mono">Dữ liệu thời gian thực</span>
                            </div>
                            {/* KPI Grid */}
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                              <div className="p-3 rounded-xl bg-brand-500/[0.04] border border-brand-500/20 space-y-1">
                                <span className="text-[10px] text-white/60 uppercase font-bold tracking-wider block">Báo cáo tuần</span>
                                <span className="text-xl font-black font-mono text-brand-300">{num(resultObj.reports_this_week) || 0}</span>
                              </div>
                              <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10 space-y-1">
                                <span className="text-[10px] text-white/60 uppercase font-bold tracking-wider block">Biến động</span>
                                <span className={`text-xl font-black font-mono ${pctChange >= 0 ? 'text-danger-400' : 'text-safe-400'}`}>
                                  {(pctChange > 0 ? '+' : '') + pctChange + '%'}
                                </span>
                              </div>
                              <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10 space-y-1">
                                <span className="text-[10px] text-white/60 uppercase font-bold tracking-wider block">SĐT mới</span>
                                <span className="text-xl font-black font-mono text-warn-300">{num(resultObj.new_phones) || 0}</span>
                              </div>
                              <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10 space-y-1">
                                <span className="text-[10px] text-white/60 uppercase font-bold tracking-wider block">Web Phishing</span>
                                <span className="text-xl font-black font-mono text-danger-400">{num(resultObj.phishing_domains) || 0}</span>
                              </div>
                            </div>

                            {/* Hot Targets Lists */}
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
                              <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/10 space-y-2">
                                <span className="text-[11px] font-bold text-white/90 flex items-center gap-1.5">
                                  <i className="bi bi-fire text-danger-400"></i> Mục tiêu bị phản ánh nóng:
                                </span>
                                {hotPhones.length > 0 ? (
                                  <div className="space-y-1.5 max-h-48 overflow-y-auto">
                                    {hotPhones.map((hp, idx) => {
                                      const ho = obj(hp);
                                      const label = str(ho.target_value) || str(ho.masked) || str(hp);
                                      return (
                                        <div key={idx} className="flex items-center justify-between text-xs py-1 px-2 rounded-lg bg-black/40 border border-white/5">
                                          <span className="font-mono text-brand-300 truncate">{label}</span>
                                          <span className="text-[10px] font-bold font-mono px-1.5 py-0.2 rounded bg-danger-500/20 text-danger-300">{num(ho.count) || 1} tin</span>
                                        </div>
                                      );
                                    })}
                                  </div>
                                ) : (
                                  <p className="text-[10px] text-white/55 py-2">Không ghi nhận điểm nóng đột biến.</p>
                                )}
                              </div>

                              <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/10 space-y-2">
                                <span className="text-[11px] font-bold text-white/90 flex items-center gap-1.5">
                                  <i className="bi bi-pie-chart text-brand-400"></i> Thủ đoạn lừa đảo hàng đầu:
                                </span>
                                {topScamTypes.length > 0 ? (
                                  <div className="space-y-1.5 max-h-48 overflow-y-auto">
                                    {topScamTypes.map((st, idx) => {
                                      const so = obj(st);
                                      return (
                                        <div key={idx} className="flex items-center justify-between text-xs py-1 px-2 rounded-lg bg-black/40 border border-white/5">
                                          <span className="text-white/80 truncate text-[11px]">{str(so.scam_type) || str(so.label) || str(st)}</span>
                                          <span className="text-[10px] font-bold font-mono px-1.5 py-0.2 rounded bg-brand-500/20 text-brand-300">{num(so.count) || num(so.value)}</span>
                                        </div>
                                      );
                                    })}
                                  </div>
                                ) : (
                                  <p className="text-[10px] text-white/55 py-2">Dữ liệu đang được tổng hợp.</p>
                                )}
                              </div>
                            </div>
                          </div>
                        )}

                        {/* SPECIAL CASE 3: lookup_scam_db */}
                        {playgroundTool === 'lookup_scam_db' && resultObj.results !== undefined && (
                          <div className="space-y-3">
                            <div className="flex items-center justify-between border-b border-white/10 pb-2">
                              <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                                <i className="bi bi-database-check text-brand-400"></i> Kết Quả Tra Cứu Kho Hồ Sơ Đen
                              </span>
                              <span className="text-[11px] font-mono text-brand-300">{num(resultObj.total) || lookupItems.length} bản ghi</span>
                            </div>
                            {lookupItems.length > 0 ? (
                              <div className="space-y-2">
                                {lookupItems.map((item, idx) => {
                                  const io = obj(item);
                                  const riskLvl = str(io.risk_level);
                                  return (
                                    <div key={idx} className="p-3 rounded-xl bg-white/[0.02] border border-white/10 space-y-1.5 hover:bg-white/[0.04] transition-all">
                                      <div className="flex items-center justify-between gap-2">
                                        <div className="flex items-center gap-2 min-w-0">
                                          <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-white/10 text-white/70">{str(io.type_display) || str(io.type) || 'Chỉ số'}</span>
                                          <span className="font-mono text-xs font-bold text-brand-300 truncate">{str(io.target) || str(io.title)}</span>
                                        </div>
                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${riskLvl === 'RED' ? 'bg-danger-500/20 text-danger-300' : riskLvl === 'YELLOW' ? 'bg-warn-500/20 text-warn-300' : 'bg-safe-500/20 text-safe-300'}`}>
                                          {str(io.risk_display) || riskLvl || 'Cảnh báo'}
                                        </span>
                                      </div>
                                      <p className="text-[11px] text-white/70 leading-relaxed">{str(io.title) || str(io.scam_type_display) || str(io.description) || ''}</p>
                                    </div>
                                  );
                                })}
                              </div>
                            ) : (
                              <div className="p-6 rounded-2xl bg-safe-950/20 border border-safe-500/30 text-center space-y-2 py-8">
                                <i className="bi bi-shield-check text-safe-400 text-3xl block"></i>
                                <p className="text-xs font-bold text-white">Không ghi nhận chỉ số trong kho dữ liệu đen</p>
                                <p className="text-[11px] text-white/60 max-w-sm mx-auto">Từ khóa tra cứu hiện chưa có tiền án hoặc báo cáo lừa đảo đã xác thực trong hệ thống ShieldCall.</p>
                              </div>
                            )}
                          </div>
                        )}

                        {/* SPECIAL CASE 4: report_scam */}
                        {playgroundTool === 'report_scam' && resultObj.report_id !== undefined && (
                          <div className="p-6 rounded-2xl bg-safe-950/30 border border-safe-500/40 text-center space-y-3 py-10">
                            <div className="w-12 h-12 rounded-2xl bg-safe-500/10 border border-safe-500/30 text-safe-400 text-2xl flex items-center justify-center mx-auto">
                              <i className="bi bi-check2-circle"></i>
                            </div>
                            <div className="space-y-1">
                              <p className="text-sm font-black text-white">Báo Cáo Đã Tiếp Nhận Thành Công!</p>
                              <p className="text-xs text-safe-300 font-mono">{'Mã hồ sơ: #' + str(resultObj.report_id) + ' • Trạng thái: ' + (str(resultObj.status) || 'pending')}</p>
                            </div>
                            <p className="text-xs text-white/70 max-w-md mx-auto leading-relaxed">{str(resultObj.message) || 'Hồ sơ đã được đưa vào luồng thẩm định tự động và kiểm duyệt an ninh.'}</p>
                          </div>
                        )}

                        {/* DEFAULT CASE: THREAT SCANNERS */}
                        {(!['get_supported_banks', 'get_scam_radar_trends', 'lookup_scam_db', 'report_scam'].includes(playgroundTool) ||
                          (!resultIsArray && resultObj.risk_score !== undefined) ||
                          resultObj.overall_risk_score !== undefined) && (
                          <div className="space-y-5">
                            {/* Verdict Banner Card */}
                            <div className={`p-4 rounded-2xl border transition-all ${riskUi.banner}`}>
                              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                                <div className="space-y-1">
                                  <div className="flex items-center gap-2">
                                    <i className={`bi text-lg ${riskUi.icon}`}></i>
                                    <span className={`text-xs font-black uppercase tracking-wider ${riskUi.text}`}>{'MỨC ĐỘ: ' + riskLevel}</span>
                                  </div>
                                  <p className="text-xs text-white/80 font-sans">
                                    {str(resultObj.suggested_action) ? 'Hành động khuyến nghị: ' + str(resultObj.suggested_action) : 'Đã hoàn tất đối soát chỉ số an ninh.'}
                                  </p>
                                </div>

                                <div className="text-right flex sm:flex-col items-center sm:items-end justify-between">
                                  <span className="text-[10px] text-white/60 uppercase font-bold tracking-wider">Điểm Rủi Ro</span>
                                  <div className={`text-2xl font-black font-mono ${riskUi.text}`}>
                                    <span>{getResultRiskScore()}</span><span className="text-xs text-white/55">/100</span>
                                  </div>
                                </div>
                              </div>

                              {/* Progress Bar Gauge */}
                              <div className="w-full h-1.5 rounded-full bg-black/40 mt-3 overflow-hidden">
                                <div className={`h-full rounded-full transition-all duration-500 ${riskUi.bar}`} style={{ width: `${Math.min(100, Math.max(5, getResultRiskScore()))}%` }}></div>
                              </div>
                            </div>

                            {/* Detected Threats List */}
                            <div className="space-y-2">
                              <label className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                                <i className="bi bi-exclamation-triangle text-warn-400"></i> Dấu hiệu phát hiện:
                              </label>
                              {threats.length > 0 ? (
                                <div className="space-y-1.5">
                                  {threats.map((threat, idx) => (
                                    <div key={idx} className="flex items-start gap-2 p-2.5 rounded-xl bg-white/[0.03] border border-white/10 text-xs text-white/90">
                                      <i className="bi bi-arrow-right-circle text-brand-400 shrink-0 mt-0.5"></i>
                                      <span className="leading-relaxed">{threat}</span>
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <div className="p-3 rounded-xl bg-safe-500/10 border border-safe-500/20 text-safe-300 text-xs flex items-center gap-2">
                                  <i className="bi bi-check-circle-fill text-safe-400"></i>
                                  <span>Không ghi nhận dấu hiệu độc hại hoặc cảnh báo gian lận nào trong cơ sở dữ liệu.</span>
                                </div>
                              )}
                            </div>

                            {/* Key Telemetry Cards Grid */}
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                              <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10 space-y-1">
                                <span className="text-[10px] text-white/55 uppercase font-bold tracking-wider block">Thực thể</span>
                                <span className="font-mono text-xs font-bold text-brand-300 truncate block">
                                  {str(resultObj.phone) || str(resultObj.domain) || str(resultObj.bank) || str(resultObj.email) || playgroundTool}
                                </span>
                              </div>
                              <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10 space-y-1">
                                <span className="text-[10px] text-white/55 uppercase font-bold tracking-wider block">Hình thức</span>
                                <span className="font-mono text-xs font-bold text-white/80 truncate block">
                                  {str(resultObj.scam_type) || str(resultObj.line_type) || (num(resultObj.entities_count) ? num(resultObj.entities_count) + ' thực thể' : 'Tiêu chuẩn')}
                                </span>
                              </div>
                              <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10 space-y-1">
                                <span className="text-[10px] text-white/55 uppercase font-bold tracking-wider block">Cộng đồng</span>
                                <span className="font-mono text-xs font-bold text-white/80 block">
                                  {typeof resultObj.report_count === 'number'
                                    ? resultObj.report_count + ' báo cáo'
                                    : num(resultObj.reports_this_week)
                                      ? num(resultObj.reports_this_week) + ' tuần này'
                                      : 'Chưa có báo cáo'}
                                </span>
                              </div>
                              <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10 space-y-1">
                                <span className="text-[10px] text-white/55 uppercase font-bold tracking-wider block">Trạng thái</span>
                                <span className="font-mono text-xs font-bold text-safe-400 block">{str(resultObj.status) || 'Hoàn tất'}</span>
                              </div>
                            </div>

                            {/* Explanation / AI Analysis Box */}
                            {(explanation || recommendedActions.length > 0) && (
                              <div className="space-y-2">
                                <label className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                                  <i className="bi bi-lightbulb-fill text-brand-400"></i> Phân tích chi tiết & Hành động khuyến nghị:
                                </label>
                                <div className="p-4 rounded-xl bg-black/50 border border-white/10 text-xs space-y-3 leading-relaxed text-white/80">
                                  {/* Bản gốc dùng x-html cho explanation. */}
                                  {!!explanation && <div className="font-sans text-white/90" dangerouslySetInnerHTML={{ __html: sanitizeHtml(explanation) }}></div>}
                                  {recommendedActions.length > 0 && (
                                    <div className="space-y-1.5 pt-2 border-t border-white/10">
                                      {recommendedActions.map((act, aIdx) => (
                                        <div key={aIdx} className="flex items-start gap-2 text-white/70">
                                          <i className="bi bi-shield-check text-brand-400 shrink-0 mt-0.5"></i>
                                          <span>{act}</span>
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* TAB 2: RAW JSON CODE */}
                    {playgroundTab === 'json' && (
                      <div className="space-y-2">
                        <pre className="text-brand-300 text-xs font-mono select-all leading-relaxed whitespace-pre overflow-x-auto"><code>{JSON.stringify(playgroundResult, null, 2)}</code></pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Real-world Interaction Workflow Section */}
      <div id="real-world-dialogue" className="space-y-6 pt-6">
        <div className="border-b border-white/10 pb-4">
          <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-brand2-400/10 text-brand2-300 text-[10px] font-black uppercase tracking-wider mb-2">
            <i className="bi bi-chat-heart-fill"></i> Kịch bản thực chiến
          </div>
          <h2 className="text-2xl font-black text-white tracking-tight">Kịch Bản Chatbot Sau Khi Tích Hợp ShieldCall MCP</h2>
          <p className="text-xs text-white/60">Mô phỏng cách Chatbot tự động nhận diện mối nguy và kích hoạt công cụ bảo mật khi người dùng đặt câu hỏi.</p>
        </div>

        <div className="liquid-card overflow-hidden border border-white/10 bg-[var(--sc-panel)]/90 rounded-3xl shadow-2xl">
          {/* macOS Window Header Bar */}
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/10 bg-white/[0.03]">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-[var(--sc-mac-red)] inline-block"></span>
              <span className="w-3 h-3 rounded-full bg-[var(--sc-mac-yellow)] inline-block"></span>
              <span className="w-3 h-3 rounded-full bg-[var(--sc-mac-green)] inline-block"></span>
              <span className="ml-3 text-xs font-mono text-white/60">ShieldCall Sentry Session #live-simulation</span>
            </div>
            <div className="flex items-center gap-2 text-[11px] font-mono text-brand-400">
              <span className="w-2 h-2 rounded-full bg-brand-400 animate-pulse"></span>
              <span>MCP Active</span>
            </div>
          </div>

          <div className="p-6 md:p-8 space-y-4">
            {/* Message 1: User */}
            <div className="flex items-start gap-3.5">
              <div className="w-8 h-8 rounded-xl bg-white/10 flex items-center justify-center text-white/80 shrink-0 text-xs font-bold border border-white/10">
                User
              </div>
              <div className="space-y-1.5 max-w-2xl">
                <p className="text-[11px] font-bold text-white/60">Người Dùng</p>
                <div className="p-4 rounded-2xl bg-white/[0.04] border border-white/10 text-xs text-white/90 leading-relaxed">
                  Tôi vừa nhận được tin nhắn từ số điện thoại <strong>0912345678</strong> xưng là cán bộ công an, bảo tôi cài app Dịch Vụ Công tại link <strong>dichvucong-vn.top</strong> rồi chuyển 2 triệu vào STK <strong>MBBank 0987654321</strong> để bảo lãnh tài khoản. Bạn kiểm tra giúp tôi có an toàn không?
                </div>
              </div>
            </div>

            {/* Vertical Connector Line & Behind the Scenes: MCP Tool Call */}
            <div className="ml-4 pl-7 border-l-2 border-brand-500/30 py-2">
              <div className="p-4 rounded-2xl bg-[var(--sc-panel)] border border-brand-500/40 text-xs font-mono space-y-2.5 max-w-3xl shadow-lg shadow-brand-950/40">
                <div className="flex items-center justify-between text-[11px] text-brand-300 border-b border-white/10 pb-2">
                  <span className="font-bold flex items-center gap-1.5">
                    <i className="bi bi-gear-fill animate-spin text-xs"></i> MCP Server Automatic Trigger:
                  </span>
                  <span className="text-white/55">Tool: scan_full_incident()</span>
                </div>
                <div className="text-white/75 text-[11px] space-y-1">
                  <p><span className="text-brand-400">phone:</span> "0912345678" → <span className="text-warn-400">Đầu số dịch vụ / Nghi vấn số ảo</span></p>
                  <p><span className="text-brand-400">url:</span> "dichvucong-vn.top" → <span className="text-danger-400">Tên miền giả mạo Cổng Dịch Vụ Công Quốc Gia (Không SSL)</span></p>
                  <p><span className="text-brand-400">bank:</span> "MBBank" - <span className="text-brand-400">account:</span> "0987654321" → <span className="text-danger-400">Tài khoản có dấu hiệu gian lận</span></p>
                  <p className="text-danger-400 font-bold pt-1 border-t border-white/5">→ Overall Risk Score: 100/100 (CRITICAL / RED)</p>
                </div>
              </div>
            </div>

            {/* Message 2: Chatbot */}
            <div className="flex items-start gap-3.5">
              <div className="w-8 h-8 rounded-xl bg-brand-400 text-black flex items-center justify-center shrink-0 text-xs font-black shadow-lg shadow-brand-400/20">
                AI
              </div>
              <div className="space-y-1.5 max-w-3xl">
                <p className="text-[11px] font-bold text-brand-300">ShieldCall Sentry (Claude / Cursor / ChatGPT)</p>
                <div className="p-5 rounded-2xl bg-brand-500/[0.04] border border-brand-500/30 text-xs text-white/90 space-y-3 leading-relaxed">
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-danger-500/20 text-danger-400 font-black text-[11px] border border-danger-500/30">
                    <i className="bi bi-shield-x"></i> CẢNH BÁO: ĐÂY LÀ HÀNH VI LỪA ĐẢO NGUY HIỂM (ĐIỂM RỦI RO: 100/100)
                  </div>
                  <p>
                    Qua tra cứu trực tiếp trên hệ thống cơ sở dữ liệu ShieldCall VN, toàn bộ các dấu vết bạn vừa cung cấp đều là thủ đoạn mạo danh cơ quan chức năng:
                  </p>
                  <ul className="list-disc list-inside space-y-1 pl-1 text-white/80">
                    <li><strong>Website giả mạo:</strong> Tên miền <code>dichvucong-vn.top</code> là trang nhái Cổng Dịch Vụ Công Quốc Gia (tên miền chính thống duy nhất của chính phủ là <code>dichvucong.gov.vn</code>). Trang này chứa mã độc đánh cắp tài khoản.</li>
                    <li><strong>Số tài khoản rủi ro:</strong> STK MBBank được sử dụng để nhận tiền bảo lãnh giả. Cơ quan công an không bao giờ yêu cầu người dân chuyển tiền qua tài khoản cá nhân.</li>
                    <li><strong>Số điện thoại:</strong> Thuộc diện đầu số ảo VoIP gọi qua Internet.</li>
                  </ul>
                  <div className="p-3 rounded-xl bg-danger-500/10 border border-danger-500/20 text-danger-200 text-xs font-bold space-y-1">
                    <p>Checklist hành động khẩn cấp:</p>
                    <p>1. TUYỆT ĐỐI KHÔNG chuyển 2 triệu đồng và KHÔNG truy cập vào liên kết trên.</p>
                    <p>2. Chặn ngay số điện thoại 0912345678.</p>
                    <p>3. Trình báo cho Công an phường/xã gần nhất nếu đối tượng liên tục đe dọa.</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Troubleshooting & FAQ Section */}
      <div id="troubleshooting" className="space-y-6 pt-6">
        <div className="border-b border-white/10 pb-4">
          <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-warn-400/10 text-warn-300 text-[10px] font-black uppercase tracking-wider mb-2">
            <i className="bi bi-wrench-adjustable-circle"></i> Trợ giúp kỹ thuật
          </div>
          <h2 className="text-2xl font-black text-white tracking-tight">Xử Lý Sự Cố & Câu Hỏi Thường Gặp (Troubleshooting)</h2>
          <p className="text-xs text-white/60">Các vấn đề thường gặp khi tích hợp Model Context Protocol và giải pháp khắc phục.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="liquid-card p-6 space-y-3 bg-white/[0.02]">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-brand-400/10 text-brand-300 text-xs flex items-center justify-center font-bold">1</span>
              Lỗi "command not found: python" trong Claude / Cursor?
            </h3>
            <p className="text-xs text-white/70 leading-relaxed">
              Trên macOS hoặc Linux, lệnh <code>python</code> mặc định có thể không trỏ đến Python 3 hoặc môi trường ảo dự án. Khắc phục bằng cách thay chữ <code>python</code> trong file cấu hình bằng đường dẫn tuyệt đối:
            </p>
            <div className="p-2.5 rounded-xl bg-black/50 border border-white/10 font-mono text-[11px] text-brand-300 select-all">
              /usr/bin/python3
            </div>
            <p className="text-[11px] text-white/60">Mẹo: Mở Terminal và gõ <code>which python3</code> (macOS/Linux) hoặc <code>where python</code> (Windows) để lấy chính xác đường dẫn.</p>
          </div>

          <div className="liquid-card p-6 space-y-3 bg-white/[0.02]">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-brand-400/10 text-brand-300 text-xs flex items-center justify-center font-bold">2</span>
              Làm sao biết Chatbot đã nhận diện thành công 10 công cụ?
            </h3>
            <p className="text-xs text-white/70 leading-relaxed">
              Sau khi cập nhật file cấu hình và khởi động lại phần mềm:
            </p>
            <ul className="text-xs text-white/70 list-disc list-inside space-y-1 pl-1">
              <li><strong>Claude Desktop:</strong> Biểu tượng chiếc búa (Hammer) hiển thị 10 công cụ kèm dấu kiểm xanh.</li>
              <li><strong>Cursor:</strong> Tab <em>Settings → Features → MCP Servers</em> hiển thị trạng thái <strong>Connected</strong> (chấm xanh lá).</li>
              <li><strong>Windsurf:</strong> Giao diện Cascade nhận diện server <code>shieldcall</code>.</li>
            </ul>
          </div>

          <div className="liquid-card p-6 space-y-3 bg-white/[0.02]">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-brand-400/10 text-brand-300 text-xs flex items-center justify-center font-bold">3</span>
              Hạn mức gọi API được tính và làm mới (Reset) khi nào?
            </h3>
            <p className="text-xs text-white/70 leading-relaxed">
              Mỗi tài khoản miễn phí được cấp <strong>500 requests/ngày</strong> và <strong>60 requests/phút</strong>. Hạn mức ngày được làm mới tự động vào <strong>00:00 UTC</strong> (tức 07:00 sáng theo giờ Việt Nam). Bạn có thể theo dõi thanh dung lượng thời gian thực tại <Link href="/dashboard/?tab=api_keys" className="text-brand-300 underline font-bold">Dashboard cá nhân</Link>.
            </p>
          </div>

          <div className="liquid-card p-6 space-y-3 bg-white/[0.02]">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-brand-400/10 text-brand-300 text-xs flex items-center justify-center font-bold">4</span>
              Triển khai qua mạng từ xa (SSE Transport / Docker)?
            </h3>
            <p className="text-xs text-white/70 leading-relaxed">
              Nếu bạn muốn chạy MCP Server trên máy chủ Linux từ xa cho cả đội ngũ sử dụng mà không cần cài Python trên từng máy cá nhân, khởi chạy lệnh sau:
            </p>
            <div className="p-2.5 rounded-xl bg-black/50 border border-white/10 font-mono text-[11px] text-brand-300 select-all">
              python shieldcall_mcp.py --transport sse --host 0.0.0.0 --port 8002
            </div>
            <p className="text-[11px] text-white/60">Khi đó phía Client chỉ cần khai báo: <code>"url": "http://ip-may-chu:8002/sse"</code>.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
