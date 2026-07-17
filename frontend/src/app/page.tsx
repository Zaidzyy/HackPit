"use client";

import { motion } from "framer-motion";

export default function Home() {
  return (
    <main className="relative flex min-h-screen w-full flex-1 items-center justify-center overflow-hidden bg-neutral-950 text-neutral-50">
      {/* ambient glow */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-60"
        style={{
          background:
            "radial-gradient(60% 60% at 50% 40%, rgba(56,189,248,0.14), transparent 70%), radial-gradient(40% 40% at 70% 70%, rgba(168,85,247,0.12), transparent 70%)",
        }}
      />
      {/* subtle grid */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            "linear-gradient(to right, #fff 1px, transparent 1px), linear-gradient(to bottom, #fff 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
      />

      <motion.h1
        initial={{ opacity: 0, y: 12, filter: "blur(8px)" }}
        animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
        transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
        className="relative z-10 select-none bg-gradient-to-b from-white to-neutral-400 bg-clip-text text-6xl font-semibold tracking-tight text-transparent sm:text-8xl"
      >
        HackPit
      </motion.h1>
    </main>
  );
}
