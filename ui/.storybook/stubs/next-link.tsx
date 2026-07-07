import React from "react";

// Storybook renders components in a plain Vite/React runtime without the
// Next.js app router, so `next/link` is aliased to this lightweight anchor
// (see .storybook/main.ts). Behaviour matches Link closely enough for the
// dashboard components under test: it forwards className/onClick/children and
// coerces object hrefs to a string.
type NextLinkProps = Omit<
  React.AnchorHTMLAttributes<HTMLAnchorElement>,
  "href"
> & {
  href: string | { pathname?: string };
};

const Link = React.forwardRef<HTMLAnchorElement, NextLinkProps>(function Link(
  { href, children, ...rest },
  ref,
) {
  const to = typeof href === "string" ? href : href?.pathname ?? "#";
  return (
    <a ref={ref} href={to} {...rest}>
      {children}
    </a>
  );
});

export default Link;
