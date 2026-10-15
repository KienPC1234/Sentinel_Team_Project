import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/McpGuide';

export const metadata = pageMeta({
  title: 'Tích hợp MCP Server',
  description:
    'Tích hợp ShieldCall MCP Server vào Claude Desktop, Claude Chat, Cursor và các trợ lý AI để kiểm tra lừa đảo ngay trong hội thoại.',
  path: '/mcp/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
