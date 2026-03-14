"use client"
import * as Dialog from "@radix-ui/react-dialog"
import { cn } from "@/lib/utils"

interface ConfirmDialogProps {
  open: boolean
  title: string
  description: string
  confirmLabel?: string
  cancelLabel?: string
  variant?: "default" | "danger" | "warning"
  onConfirm: () => void
  onCancel: () => void
  isPending?: boolean
}

const variantStyles: Record<string, string> = {
  default: "bg-primary text-primary-foreground hover:bg-primary/90",
  danger: "bg-red-500 text-white hover:bg-red-600",
  warning: "bg-amber-500 text-black hover:bg-amber-600",
}

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  variant = "default",
  onConfirm,
  onCancel,
  isPending = false,
}: ConfirmDialogProps) {
  return (
    <Dialog.Root open={open} onOpenChange={o => { if (!o) onCancel() }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-50" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-50 bg-card border border-border rounded-lg p-6 w-full max-w-sm focus:outline-none"
          aria-describedby="confirm-dialog-desc"
        >
          <Dialog.Title className="font-bold text-sm">{title}</Dialog.Title>
          <Dialog.Description id="confirm-dialog-desc" className="text-sm text-muted-foreground mt-2">
            {description}
          </Dialog.Description>
          <div className="flex gap-2 justify-end mt-5">
            <button
              onClick={onCancel}
              className="px-3 py-1.5 text-sm border border-border rounded hover:bg-muted"
            >
              {cancelLabel}
            </button>
            <button
              onClick={onConfirm}
              disabled={isPending}
              className={cn(
                "px-3 py-1.5 text-sm rounded disabled:opacity-50 flex items-center gap-1.5",
                variantStyles[variant],
              )}
            >
              {isPending && (
                <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              )}
              {confirmLabel}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
