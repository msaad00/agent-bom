import { Suspense } from "react";
import InventoryClient from "./InventoryClient";

export default function InventoryPage() {
  return <Suspense fallback={null}><InventoryClient /></Suspense>;
}
