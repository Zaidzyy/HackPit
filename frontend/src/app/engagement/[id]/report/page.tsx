import { ReportScreen } from "@/components/ReportScreen";

export default async function ReportPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <ReportScreen id={id} />;
}
