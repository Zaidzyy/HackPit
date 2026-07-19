import { PrintReport } from "@/components/PrintReport";

export default async function ReportPrintPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <PrintReport id={id} />;
}
