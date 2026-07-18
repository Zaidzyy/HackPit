import { CategoryScreen } from "@/components/CategoryScreen";

export default async function CategoryPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  return <CategoryScreen slug={slug} />;
}
