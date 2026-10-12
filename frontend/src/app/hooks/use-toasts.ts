// 通知（toasts）域：toast 队列 + addToast 归仓（阶段 2 收尾档）。
// renderToasts 的 JSX 渲染仍留在 page（视图代码），本 hook 只管状态与生命周期。

import { useCallback, useState } from "react";
import type { Toast } from "../types";
import { makeId } from "../app-meta";

export function useToasts() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((message: string, type: Toast["type"] = "info") => {
    const toast: Toast = { id: makeId("toast"), type, message };
    setToasts((current) => [...current, toast]);
    window.setTimeout(() => {
      setToasts((current) => current.filter((item) => item.id !== toast.id));
    }, 3200);
  }, []);

  return { toasts, addToast };
}
