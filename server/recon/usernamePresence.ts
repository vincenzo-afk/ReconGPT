import type { ModuleResult, ReconFinding, ReconOptions, ReconTarget, RiskLevel } from "./types";
import { IDENTITY_SOURCE_POLICY, identityMetadata } from "./identitySafety";

type Platform = { name: string; url: string; automated?: boolean };

const uid = () => crypto.randomUUID().slice(0, 16);
const encodeHandle = (value: string) => encodeURIComponent(value.replace(/^@/, "").trim());

/**
 * A versioned public-profile catalogue. Only the deliberately small `automated`
 * subset is requested by ReconGPT; all other links are review pivots so a run
 * does not turn into high-volume cross-platform probing.
 */
const PLATFORM_ROWS: Array<[string, string, boolean?]> = [
  ["GitHub", "https://github.com/{u}", true], ["GitLab", "https://gitlab.com/{u}", true], ["Bitbucket", "https://bitbucket.org/{u}", true], ["Codeberg", "https://codeberg.org/{u}", true], ["SourceHut", "https://sr.ht/~{u}", true], ["Dev.to", "https://dev.to/{u}", true], ["Hacker News", "https://news.ycombinator.com/user?id={u}", true], ["Reddit", "https://www.reddit.com/user/{u}", true], ["Medium", "https://medium.com/@{u}", true], ["Hashnode", "https://hashnode.com/@{u}"],
  ["Mastodon Social", "https://mastodon.social/@{u}", true], ["Bluesky", "https://bsky.app/profile/{u}.bsky.social", true], ["X", "https://x.com/{u}", true], ["Threads", "https://www.threads.net/@{u}"], ["Tumblr", "https://{u}.tumblr.com"], ["Pinterest", "https://www.pinterest.com/{u}"], ["TikTok", "https://www.tiktok.com/@{u}"], ["Instagram", "https://www.instagram.com/{u}/"], ["Facebook", "https://www.facebook.com/{u}"], ["LinkedIn", "https://www.linkedin.com/in/{u}"],
  ["YouTube", "https://www.youtube.com/@{u}"], ["Twitch", "https://www.twitch.tv/{u}"], ["Vimeo", "https://vimeo.com/{u}"], ["Dailymotion", "https://www.dailymotion.com/{u}"], ["Kick", "https://kick.com/{u}"], ["SoundCloud", "https://soundcloud.com/{u}"], ["Bandcamp", "https://bandcamp.com/{u}"], ["Spotify", "https://open.spotify.com/user/{u}"], ["Last.fm", "https://www.last.fm/user/{u}"], ["Mixcloud", "https://www.mixcloud.com/{u}"],
  ["Steam", "https://steamcommunity.com/id/{u}"], ["Xbox", "https://www.xbox.com/en-US/play/user/{u}"], ["PlayStation", "https://psnprofiles.com/{u}"], ["Nintendo", "https://accounts.nintendo.com/{u}"], ["Chess.com", "https://www.chess.com/member/{u}"], ["Lichess", "https://lichess.org/@/{u}"], ["Roblox", "https://www.roblox.com/users/profile?username={u}"], ["Minecraft", "https://namemc.com/profile/{u}"], ["Speedrun", "https://www.speedrun.com/users/{u}"], ["BoardGameGeek", "https://boardgamegeek.com/user/{u}"],
  ["Keybase", "https://keybase.io/{u}"], ["Stack Overflow", "https://stackoverflow.com/users/{u}"], ["Stack Exchange", "https://stackexchange.com/users/{u}"], ["Kaggle", "https://www.kaggle.com/{u}"], ["Replit", "https://replit.com/@{u}"], ["Glitch", "https://glitch.com/@{u}"], ["CodePen", "https://codepen.io/{u}"], ["JSFiddle", "https://jsfiddle.net/user/{u}"], ["NPM", "https://www.npmjs.com/~{u}"], ["PyPI", "https://pypi.org/user/{u}"],
  ["Docker Hub", "https://hub.docker.com/u/{u}"], ["Hugging Face", "https://huggingface.co/{u}"], ["Figma Community", "https://www.figma.com/@{u}"], ["Behance", "https://www.behance.net/{u}"], ["Dribbble", "https://dribbble.com/{u}"], ["ArtStation", "https://www.artstation.com/{u}"], ["DeviantArt", "https://www.deviantart.com/{u}"], ["Unsplash", "https://unsplash.com/@{u}"], ["Flickr", "https://www.flickr.com/people/{u}"], ["500px", "https://500px.com/p/{u}"],
  ["Etsy", "https://www.etsy.com/shop/{u}"], ["eBay", "https://www.ebay.com/usr/{u}"], ["Gumroad", "https://{u}.gumroad.com"], ["Ko-fi", "https://ko-fi.com/{u}"], ["Patreon", "https://www.patreon.com/{u}"], ["Buy Me a Coffee", "https://www.buymeacoffee.com/{u}"], ["Substack", "https://{u}.substack.com"], ["Product Hunt", "https://www.producthunt.com/@{u}"], ["Goodreads", "https://www.goodreads.com/{u}"], ["Letterboxd", "https://letterboxd.com/{u}"],
  ["Wattpad", "https://www.wattpad.com/user/{u}"], ["Archive of Our Own", "https://archiveofourown.org/users/{u}"], ["WordPress", "https://{u}.wordpress.com"], ["Blogger", "https://{u}.blogspot.com"], ["About.me", "https://about.me/{u}"], ["Linktree", "https://linktr.ee/{u}"], ["Carrd", "https://{u}.carrd.co"], ["Gravatar", "https://en.gravatar.com/{u}"], ["Disqus", "https://disqus.com/by/{u}"], ["Quora", "https://www.quora.com/profile/{u}"],
  ["Wikipedia", "https://en.wikipedia.org/wiki/User:{u}"], ["Wikimedia Commons", "https://commons.wikimedia.org/wiki/User:{u}"], ["OpenStreetMap", "https://www.openstreetmap.org/user/{u}"], ["Strava", "https://www.strava.com/athletes/{u}"], ["Duolingo", "https://www.duolingo.com/profile/{u}"], ["ResearchGate", "https://www.researchgate.net/profile/{u}"], ["ORCID", "https://orcid.org/{u}"], ["Academia", "https://independent.academia.edu/{u}"], ["Mendeley", "https://www.mendeley.com/profiles/{u}"], ["Slideshare", "https://www.slideshare.net/{u}"],
  ["Telegram", "https://t.me/{u}"], ["Discord Invite", "https://discord.com/users/{u}"], ["Signal Community", "https://community.signalusers.org/u/{u}"], ["Matrix", "https://matrix.to/#/@{u}:matrix.org"], ["Lemmy World", "https://lemmy.world/u/{u}"], ["Pixelfed", "https://pixelfed.social/{u}"], ["PeerTube", "https://peertube.social/a/{u}"], ["Diaspora", "https://diaspora.social/u/{u}"], ["WriteFreely", "https://write.as/{u}"], ["Minds", "https://www.minds.com/{u}"],
  ["TradingView", "https://www.tradingview.com/u/{u}"], ["Codecademy", "https://www.codecademy.com/profiles/{u}"], ["LeetCode", "https://leetcode.com/u/{u}"], ["HackerRank", "https://www.hackerrank.com/profile/{u}"], ["TryHackMe", "https://tryhackme.com/p/{u}"], ["Hack The Box", "https://app.hackthebox.com/users/{u}"], ["Thingiverse", "https://www.thingiverse.com/{u}/designs"], ["Printables", "https://www.printables.com/@{u}"], ["Instructables", "https://www.instructables.com/member/{u}"], ["Yelp", "https://www.yelp.com/user_details?userid={u}"],
];
export const USERNAME_PLATFORM_CATALOG: Platform[] = PLATFORM_ROWS.map(([name, url, automated]) => ({ name, url, automated: Boolean(automated) }));

export function profileUrl(pattern: string, username: string) { return pattern.replaceAll("{u}", encodeHandle(username)); }

export function usernameCheckBudget(intensity: ReconOptions["dorkIntensity"]) {
  return intensity === "focused" ? 6 : intensity === "deep" ? 18 : 12;
}

function statusFromResponse(response: Response, username: string, text: string) {
  if (response.status === 404 || response.status === 410) return "not-found";
  if (response.status === 401 || response.status === 403 || response.status === 429) return "restricted";
  if (response.ok && text.toLowerCase().includes(username.toLowerCase())) return "public-profile-signal";
  if (response.ok || (response.status >= 300 && response.status < 400)) return "indeterminate";
  return "unavailable";
}

async function checkPlatform(platform: Platform, username: string) {
  const url = profileUrl(platform.url, username);
  try {
    const response = await fetch(url, { redirect: "manual", headers: { "User-Agent": "ReconGPT/2.2 (bounded-public-username-research)", Accept: "text/html,application/xhtml+xml" }, signal: AbortSignal.timeout(5_000) });
    const text = response.ok ? (await response.text()).slice(0, 24_000) : "";
    return { platform: platform.name, url, status: statusFromResponse(response, username, text), httpStatus: response.status };
  } catch {
    return { platform: platform.name, url, status: "unavailable", httpStatus: null };
  }
}

export async function publicUsernamePresence(target: ReconTarget, options: ReconOptions): Promise<ModuleResult> {
  const username = target.normalized.replace(/^@/, "");
  const automated = USERNAME_PLATFORM_CATALOG.filter(platform => platform.automated).slice(0, usernameCheckBudget(options.dorkIntensity));
  const checks = [] as Awaited<ReturnType<typeof checkPlatform>>[];
  for (const platform of automated) checks.push(await checkPlatform(platform, username));
  const signals = checks.filter(item => item.status === "public-profile-signal");
  const limitations = [...IDENTITY_SOURCE_POLICY.usernamePresence.limitations, `The ${USERNAME_PLATFORM_CATALOG.length}-platform catalogue is intentionally sampled at ${automated.length} automated source(s) for this ${options.dorkIntensity} run; remaining patterns are manual-review links.`];
  const severity: RiskLevel = signals.length >= 6 ? "medium" : "low";
  const record: ReconFinding = {
    id: uid(), moduleId: "username-presence", category: "Identity", title: "Bounded public username-presence research",
    summary: `Collected ${signals.length} public profile signal(s) from ${checks.length} bounded automated URL check(s). These results are analyst-review leads and do not establish that accounts belong to the target individual.`,
    severity, confidence: signals.length ? 74 : 62, sourceUrl: checks[0]?.url,
    evidenceQuality: "lead", leadStatus: "review", collectedAt: new Date().toISOString(), sourceCount: checks.length,
    ...identityMetadata("public", "public-source"), limitations,
    data: { username, catalogVersion: "2026.08", catalogSize: USERNAME_PLATFORM_CATALOG.length, automatedBudget: automated.length, checks, publicProfileSignals: signals, manualReviewLinks: USERNAME_PLATFORM_CATALOG.filter(platform => !platform.automated).slice(0, 100).map(platform => ({ platform: platform.name, url: profileUrl(platform.url, username) })), policy: IDENTITY_SOURCE_POLICY.usernamePresence },
    entities: signals.map(signal => ({ type: "social_profile" as const, value: signal.url, label: signal.platform, confidence: 68, metadata: { username, presenceStatus: signal.status } })),
  };
  return { findings: [record], notices: checks.filter(item => item.status === "restricted").length ? ["Some public profile endpoints restricted automated access. They are not retried or treated as absent."] : undefined };
}

export const usernamePresenceForTests = { profileUrl, usernameCheckBudget, statusFromResponse, catalogSize: () => USERNAME_PLATFORM_CATALOG.length };
