import Link from "next/link"

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[50vh] gap-4">
      <h2 className="text-2xl font-semibold">404 — Page Not Found</h2>
      <p className="text-sm text-muted-foreground">
        The page you&apos;re looking for doesn&apos;t exist.
      </p>
      <Link
        href="/"
        className="px-4 py-2 text-sm rounded-md bg-primary text-white hover:bg-primary/80 transition-colors"
      >
        Go Home
      </Link>
    </div>
  )
}
