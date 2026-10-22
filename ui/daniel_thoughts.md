Fixes:
CLI: 1. Look at the policy/known hosts thing Jules was talking about. Clean this up. While there can we make things prettier on the CLI, and clean up resources/ sandboxes/ etc. ?
Needs a walkthrough/onboarding/guide.
Make a Sentinel (establishes policies, manages network, holds credentials). Policies are set to reasonable defaults. You can easily change this later. It names this actor as ‘my computer’ / does it automatically.
(agent -> actor, I think it’s a better term)
It starts with one connection added - tinfoil, with your key
Page navigates you to making a sandbox as the next thing to do. Sandbox spins up & you can ssh in.
Make a request - it shows up in activity. Make an api request to something not set up. It fails.
Add a new connection, and make a request to that. It works.
Monitor Proxy. The monitor should expose a surface exactly the same as tinfoils proxy. This way it’s super easy to use tinfoil things when inside it!!!! Also maybe it starts with your tinfoil key there.

Play by play:

1. Entering an ssh key the ssh key box isn’t wide enough

2. The cli has too much stuff in it & it’s not nicely colored.

dmccanns@DanielsComputer ~ % tinfoil monitor open daniel1
Looking up Monitor daniel1
This connection resolves to config:

tinfoil/containers@1dd86c2ef52807f86ba049f0943693343b41db925f1f28eedf707f0f97d7e9b4@sha256:1dd86c2ef52807f86ba049f0943693343b41db925f1f28eedf707f0f97d7e9b4

It is not in your known configs. The reference comes from Tinfoil;
cross-check it against your own build or deploy records if unsure.
Trust it and record as "project"? [y/N] y
Recorded tinfoil/containers@1dd86c2ef52807f86ba049f0943693343b41db925f1f28eedf707f0f97d7e9b4@sha256:1dd86c2ef52807f86ba049f0943693343b41db925f1f28eedf707f0f97d7e9b4 as project in /Users/dmccanns/.tinfoil/known-configs.json
Monitor daniel1: running.
Back up the encryption credentials in /Users/dmccanns/.tinfoil/resources/163e645c17c3fee6c9f284ee92f6581fa2c3e28cb751f832eae4e0b914a61aff/20a217d1-026a-4ad0-84a5-48908e69bb20. Your SSH key alone cannot recover this resource.
Verifying attestation and SSH host key for daniel1.tinfoil.containers.tinfoil.dev
Monitor daniel1 attestation verified.
Connecting to Monitor daniel1 over attested SSH
Unlocking Monitor daniel1 encrypted state
Monitor daniel1 unlocked.
Opening the local Monitor panel
Local Monitor panel: http://127.0.0.1:56548/app/#session=UIi2zH2eMslGwC-qgJCVIXt3wlEjZ02ddnanTa2qtL8
Keep this command running. Ctrl-C closes the SSH connection. Owner credentials stay out of the browser.
Press Enter to open the Monitor in your browser.

3. Set up your monitor

It doesn’t explain what all this means, also do I have the ability to change this later, also what is paid AI inference, also what is TCP. It should just be offline to start, and then once you want network it allows you to switch to Known, and then later if you really want it you can switch to Open. 4. I’m in the monitor and I’m very confused. What am I looking at? What is an agent?
Agent seems like an accessor/ an actor.
Presumably if I make two monitors they don’t share policies.
Why don’t sandboxes show up in my monitors?

5. Settings > policy is confusing to me. Is this the same editor as before? Why does it look different? I don’t like it. I would like to make this much much simpler.
   Also can I have my ai poke at the monitor settings?
   Yes, just give it URL locally & it can edit & read.

6. I’m creating a new sandbox. Why is it grayed out? Why can’t I create another sandbox at the same time?

7. Why does tinfoil cli have config.json > api keys just sitting there? What is resources? Is it different than sandboxes/ ?

Everything is so overwhelming how should I actually be doing anything??

8. I’m confused about what specifically the monitor looks at. It seems like it looks just at network requests. But like there are other things I want to have it look at, like harness level things. Like loaning credentials to agent processes that want this. That’s the main case, putting an agent on this sandbox, right?

^ Adding on: the monitor is basically an off device credential store, though it only kicks in during network requests (by nature I think, though should it always be like this, idk). It should be easy to use it from my comptuer
