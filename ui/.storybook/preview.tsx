import React from "react";
import type { Decorator, Preview } from "@storybook/react-vite";

import "../app/globals.css";

// Toggle the same `data-theme` attribute the app uses so stories can be viewed
// in either the dark (default) or light token set.
function ThemeFrame({
  theme,
  children,
}: {
  theme: "dark" | "light";
  children: React.ReactNode;
}) {
  React.useEffect(() => {
    const root = document.documentElement;
    if (theme === "light") {
      root.setAttribute("data-theme", "light");
    } else {
      root.removeAttribute("data-theme");
    }
  }, [theme]);
  return (
    <div className="font-sans bg-background text-foreground min-h-screen p-6">
      {children}
    </div>
  );
}

const withTheme: Decorator = (Story, context) => (
  <ThemeFrame theme={context.globals.theme === "light" ? "light" : "dark"}>
    <Story />
  </ThemeFrame>
);

const preview: Preview = {
  parameters: {
    layout: "fullscreen",
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
  },
  globalTypes: {
    theme: {
      description: "Dashboard color theme",
      defaultValue: "dark",
      toolbar: {
        title: "Theme",
        icon: "circlehollow",
        items: [
          { value: "dark", title: "Dark" },
          { value: "light", title: "Light" },
        ],
        dynamicTitle: true,
      },
    },
  },
  decorators: [withTheme],
};

export default preview;
