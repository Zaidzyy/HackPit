"use client";

/**
 * The target-type chip row, shared by the attack-path screen and the cockpit so
 * they stay in sync. Selecting a chip sets the `target_type` sent to compose
 * (toggle off by clicking the active one). "Pentest / Bug Bounty" is a single
 * merged chip whose backend `_TARGET_CONTEXT` spans both network/host and
 * web/api terms; the profiler narrows from the goal text.
 */
export type TargetChip = { value: string; label: string };

export const TARGET_CHIPS: TargetChip[] = [
  { value: "pentest-bugbounty", label: "Pentest / Bug Bounty" },
  { value: "ctf", label: "CTF" },
  { value: "ad", label: "AD" },
];

export function TargetTypeChips({
  value,
  onChange,
  disabled = false,
}: {
  value: string | null;
  onChange: (value: string | null) => void;
  disabled?: boolean;
}) {
  return (
    <div className="hp-ap-chips" role="group" aria-label="Target type">
      {TARGET_CHIPS.map((c) => (
        <button
          key={c.value}
          type="button"
          className={`hp-ap-chip${value === c.value ? " is-on" : ""}`}
          aria-pressed={value === c.value}
          onClick={() => onChange(value === c.value ? null : c.value)}
          disabled={disabled}
        >
          {c.label}
        </button>
      ))}
    </div>
  );
}
