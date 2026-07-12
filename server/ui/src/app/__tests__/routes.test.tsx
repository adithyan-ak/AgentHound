import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { AppRoutes } from "../routes";

function renderAt(path: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AppRoutes wildcard", () => {
  it("renders a not-found view for an unknown route (no blank screen)", () => {
    renderAt("/this-route-does-not-exist");
    expect(screen.getByRole("alert")).toHaveTextContent(/page not found/i);
    expect(screen.getByText("/this-route-does-not-exist")).toBeInTheDocument();
    // The nav is still present so the user can recover.
    expect(screen.getByText(/Back to Dashboard/i)).toBeInTheDocument();
  });
});
