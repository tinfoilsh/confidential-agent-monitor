import { createSignal } from "solid-js";
import { render } from "solid-js/web";
import "../../src/dashboard.css";
import { TabBar } from "../../src/TabBar";

function TabsFixture() {
  const [value, setValue] = createSignal<string | undefined>("api");
  const [renamed, setRenamed] = createSignal(false);
  return (
    <main
      style={{ padding: "16px", width: "100%", "box-sizing": "border-box" }}
    >
      <TabBar
        label="Usage type"
        value={value()}
        onChange={setValue}
        options={[
          { value: "api", label: "API" },
          { value: "containers", label: "Containers" },
          {
            value: "bunkers",
            label: renamed() ? "Bunkers and persistent workspaces" : "Bunkers",
          },
        ]}
      />
      <p role="status">{value() ?? "No selection"}</p>
      <button onClick={() => setRenamed(true)}>Expand bunker label</button>
      <button onClick={() => setValue(undefined)}>Clear selection</button>
    </main>
  );
}

render(() => <TabsFixture />, document.getElementById("tabs-fixture")!);
