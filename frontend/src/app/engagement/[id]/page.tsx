import { EngagementScreen } from "@/components/EngagementScreen";

export default async function EngagementPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <EngagementScreen id={id} />;
}
