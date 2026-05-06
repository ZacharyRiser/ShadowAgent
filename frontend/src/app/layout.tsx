import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Shadow Agent 控制台",
  description: "影子智能体运行时安全沙箱管理端",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="zh-CN"
      className="h-full antialiased"
    >
      <body className="min-h-full bg-background text-foreground">
        {children}
      </body>
    </html>
  );
}
