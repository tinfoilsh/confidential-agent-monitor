import { For, type JSX } from "solid-js";

const PLACEHOLDER_PERIMETERS = 2;

export function Home(props: {
  perimeters: JSX.Element;
  keys: JSX.Element;
  notice?: JSX.Element;
}) {
  return (
    <main class="start-welcome start-home">
      <h1>Welcome back</h1>
      <nav class="start-monitors" aria-label="Your Perimeters">
        <p class="start-eyebrow">Your Perimeters</p>
        {props.perimeters}
      </nav>
      {props.notice}
      <section class="start-monitors" aria-label="Your keys">
        <p class="start-eyebrow">Your keys</p>
        {props.keys}
      </section>
    </main>
  );
}

function RowSkeleton(props: { recovery?: boolean }) {
  return (
    <div class="start-key-choice" aria-hidden="true">
      <span class={props.recovery ? "home-skeleton-key" : "start-status"}>
        <span
          class={`loading-skeleton ${props.recovery ? "home-skeleton-key-icon" : "home-skeleton-dot"}`}
        />
      </span>
      <div>
        <h2>
          <span class="loading-skeleton home-skeleton-name" />
        </h2>
        <p>
          <span class="loading-skeleton home-skeleton-meta" />
        </p>
      </div>
    </div>
  );
}

export function PerimetersSkeleton() {
  return (
    <>
      <span class="sr-only" role="status">
        Loading your Perimeters and bunkers…
      </span>
      <For
        each={Array.from(
          { length: PLACEHOLDER_PERIMETERS },
          (_, index) => index,
        )}
      >
        {() => <RowSkeleton />}
      </For>
    </>
  );
}

export function HomeSkeleton() {
  return (
    <Home
      perimeters={<PerimetersSkeleton />}
      keys={
        <>
          <span class="sr-only" role="status">
            Loading your keys…
          </span>
          <RowSkeleton recovery />
          <div class="monitor-actions" aria-hidden="true">
            <span class="loading-skeleton home-skeleton-button" />
            <span class="loading-skeleton home-skeleton-button" />
          </div>
        </>
      }
    />
  );
}
