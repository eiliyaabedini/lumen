/**
 * AI Pass is an OAuth account connection, never another API-key field.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AIPassConnectionCard } from "@/components/aipass/AIPassConnectionCard";

vi.mock("@/lib/auth/store", () => ({
  useAuth: () => ({ token: "lumen-token", ready: true }),
}));
vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn(), message: vi.fn() },
}));

const status = vi.fn();
const models = vi.fn();
const selectModel = vi.fn();
const disconnect = vi.fn();
const setActive = vi.fn();
vi.mock("@/lib/api/endpoints", () => ({
  AIPass: {
    status: () => status(),
    models: () => models(),
    selectModel: (model: string) => selectModel(model),
    setActive: (active: boolean) => setActive(active),
    disconnect: () => disconnect(),
  },
}));

function renderCard() {
  return render(
    <QueryClientProvider
      client={
        new QueryClient({
          defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
        })
      }
    >
      <AIPassConnectionCard />
    </QueryClientProvider>,
  );
}

describe("AIPassConnectionCard", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders Connect AI Pass without any key input", async () => {
    status.mockResolvedValue({
      available: true,
      connected: false,
      active: false,
      model: null,
      status: "disconnected",
    });
    renderCard();

    expect(await screen.findByRole("button", { name: "Connect AI Pass" })).toBeInTheDocument();
    expect(screen.queryByLabelText(/api key|token|secret/i)).toBeNull();
    expect(document.querySelector('input[type="password"]')).toBeNull();
  });

  it("loads live models after connection and can disconnect", async () => {
    const user = userEvent.setup();
    status.mockResolvedValue({
      available: true,
      connected: true,
      active: true,
      model: "live-model-a",
      status: "connected",
    });
    models.mockResolvedValue({
      models: [
        { id: "live-model-a", name: "Live A" },
        { id: "live-model-b", name: "Live B" },
      ],
    });
    disconnect.mockResolvedValue({ ok: true });
    renderCard();

    expect(await screen.findByText("Connected")).toBeInTheDocument();
    expect(await screen.findByRole("combobox", { name: "AI Pass model" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Disconnect AI Pass" }));
    expect(disconnect).toHaveBeenCalledOnce();
  });

  it("still offers disconnect when the account needs reconnection", async () => {
    const user = userEvent.setup();
    status.mockResolvedValue({
      available: true,
      connected: true,
      active: false,
      model: "live-model-a",
      status: "reauth_required",
    });
    disconnect.mockResolvedValue({ ok: true });
    renderCard();

    expect(await screen.findByRole("button", { name: "Reconnect AI Pass" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Disconnect AI Pass" }));
    expect(disconnect).toHaveBeenCalledOnce();
    expect(models).not.toHaveBeenCalled();
  });
});
