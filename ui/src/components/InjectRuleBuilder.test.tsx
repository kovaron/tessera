import { render, screen, fireEvent } from "@testing-library/react";
import { describe, test, expect, vi } from "vitest";
import InjectRuleBuilder from "./InjectRuleBuilder";

describe("InjectRuleBuilder", () => {
  test("changing type fires onChange with new type", () => {
    const onChange = vi.fn();
    render(<InjectRuleBuilder value={{ type: "bearer", secret_ref: "" }} onChange={onChange} />);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "header" } });
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ type: "header" }));
  });
});
