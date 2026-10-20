# Group Trip Planner

Everyone in the group creates an account and adds what they want from the trip. Claude then builds a day-by-day itinerary that balances everyone's preferences.

## Start it

1. Install Node.js 22.13 or newer from https://nodejs.org (one time).
2. Double-click `start.bat`. On Mac or Linux, run `npm install` and then `npm start` in this folder.
3. The window shows three things:
   - **On this computer:** the address to open yourself
   - **On your Wi-Fi:** the address to send friends on the same network
   - **Group code:** friends need this once, when they create an account

The first account you create becomes the **organiser**. The organiser's tools are on the Trip details tab:

- **See the group code.** Only the organiser can see it.
- **Make a new code.** Use this if the code was shared too widely. Existing accounts keep working.
- **Reset a forgotten password.**

Keep the window open while people use the site. Closing it stops the site, but nothing is lost.

## Building the itinerary

**Build itinerary** runs Claude Code on the planner computer. Claude Code is Anthropic's official app, and it's signed in with your Claude plan (Pro, Max or Team), so builds count toward that plan's usage. You don't need an API key.

- Claude Code has to be installed and signed in on this computer. To install it, run `npm install -g @anthropic-ai/claude-code`. To sign in, run `claude` once.
- For builds, Claude Code's tools, MCP servers, claude.ai connectors and settings hooks are all switched off. It only reads the trip details and preferences, and writes back the plan.
- A build takes about 1 to 3 minutes. It runs in the background, and the page shows the result when it's ready. A build that takes longer than 10 minutes is stopped.
- **Build limits:** to protect your Claude plan, each member can build once every 15 minutes, and the group gets 10 builds a day. The organiser can build any time.

**Using an API key instead:** if you'd rather bill builds to the Anthropic API, set these two values before starting the planner:

- `PLANNER_ENGINE=api`
- `ANTHROPIC_API_KEY=sk-ant-...`

API usage is billed at console.anthropic.com, at about 20 to 50 cents per build. The Anthropic SDK this mode uses is installed by `npm install` as an optional package.

## Where the data lives

Everything is saved in `trip.db`, a SQLite file in this folder. Passwords are stored hashed, not as plain text. To start over, stop the planner and delete `trip.db`.

## Public link (friends anywhere)

Double-click `start-public.bat` instead of `start.bat`.

1. Two windows open. One runs the planner. The other shows a link in a box ending in `.trycloudflare.com`. That's your public `https://` link.
2. **First time only:** open `http://localhost:3000` on this computer and create your organiser account. For safety, the organiser account can't be created through the public link.
3. Send the group the public link and the group code.

Things to know:

- The site is online only while this computer is on and both windows are open.
- You get a **new link every time** you start it, so send the group the new one. Accounts and answers are kept between restarts.
- The tunnel is Cloudflare's free "quick tunnel". It doesn't need an account, and it isn't meant to stay up for weeks. For a permanent link, host the planner on a service such as Render or Fly.io.
- Only run one copy at a time: use either `start.bat` or `start-public.bat`, not both.

If Windows Firewall asks whether to allow Node.js, allow it on **private** networks so friends on your Wi-Fi can connect.

Set `PORT` to use a port other than 3000.
