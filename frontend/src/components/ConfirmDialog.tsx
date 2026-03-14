"use client"
import { useId } from "react"
import * as Dialog from "@radix-ui/react-dialog"
import { AlertTriangle } from "lucide-react"
import { cn } from "@/lib/utils"

type Variant = "warning" | "danger"

export interface ConfirmDialogProps {
  open: boolean
  title: string
  description: string
  confirmLabel?: string
  cancelLabel?: string
  variant?: Variant
  isPending?: boolean
  onConfirm: () => void
  onCancel: () => void
}

const variantStyles: Record<NonNullable<ConfirmDialogProps["variant"]>, string> = {
  warning: "bg-yellow-500 hover:bg-yellow-600 text-black",
  danger: "bg-red-500 hover:bg-red-600 text-white",
}

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  variant = "warning",
  isPending = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const descId = useId()

  return (
    <Dialog.Root
      open={open}
      onOpenChange={o => {
        if (!o && !isPending) onCancel()
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-50" />
        <Dialog.Content
          aria-describedby={descId}
          className="fixed z-50 left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 bg-card border border-border rounded-lg p-6 w-full max-w-sm shadow-xl"
        >
          <div className="flex items-start gap-3 mb-4">
            <AlertTriangle
              size={18}
              className={cn(variant === "danger" ? "text-red-400" : "text-yellow-400")}
            />
            <div>
              <Dialog.Title className="font-bold text-sm mb-1">{title}</Dialog.Title>
              <Dialog.Description id={descId} className="text-sm text-muted-foreground">
                {description}
              </Dialog.Description>
            </div>
          </div>
          <div className="flex gap-2 justify-end">
            <button
              onClick={onCancel}
              disabled={isPending}
              className="px-3 py-1.5 text-sm border border-border rounded hover:bg-muted disabled:opacity-50"
            >
              {cancelLabel}
            </button>
            <button
              onClick={onConfirm}
              disabled={isPending}
              className={cn(
                "px-3 py-1.5 text-sm rounded disabled:opacity-50",
                variantStyles[variant]
              )}
            >
              {isPending ? "Please wait…" : confirmLabel}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
