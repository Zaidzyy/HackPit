import { EntryScreen } from "@/components/EntryScreen";

export default async function EntryPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <EntryScreen id={id} />;
}
