import { NextRequest, NextResponse } from "next/server";

/** Server-only configuration: never derive an upstream from request input. */
export function runtimeApiOrigin(): string {
  const env = process.env;
  const raw = env.AGENT_BOM_API_URL?.trim() || env.NEXT_PUBLIC_API_URL?.trim() || "http://localhost:8422";
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("Invalid server API origin");
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash) {
    throw new Error("Invalid server API origin");
  }
  return url.origin;
}

export function proxyApiRequest(request: NextRequest): NextResponse {
  const { pathname, search } = request.nextUrl;
  if (!(pathname === '/v1' || pathname.startsWith('/v1/') || pathname === '/health' ||
        pathname === '/version' || pathname === '/ws' || pathname.startsWith('/ws/'))) {
    return NextResponse.next();
  }
  try {
    const destination = new URL(runtimeApiOrigin());
    destination.pathname = pathname;
    destination.search = search;
    return NextResponse.rewrite(destination);
  } catch {
    return NextResponse.json({ error: "API routing is unavailable" }, { status: 503 });
  }
}
