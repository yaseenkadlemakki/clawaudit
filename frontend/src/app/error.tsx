"use client"

export default function ErrorPage({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[50vh] gap-4">
      <div className="bg-red-950/30 border border-red-500 text-red-400 rounded p-4 text-sm max-w-md text-center">
        {error.message || "Something went wrong."}
      </div>
      <button
        onClick={reset}
        className="px-4 py-2 text-sm rounded-md bg-primary text-white hover:bg-primary/80 transition-colors"
      >
        Try Again
      </button>
    </div>
  )
}
