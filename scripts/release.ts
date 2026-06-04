import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

// Find the git wrapper script
let gitWrapper = "";
let currentDir = process.cwd();
for (let i = 0; i < 5; i++) {
	const candidate = path.join(currentDir, "git-agy");
	if (fs.existsSync(candidate)) {
		gitWrapper = candidate;
		break;
	}
	currentDir = path.dirname(currentDir);
}

if (!gitWrapper) {
	console.error("❌ Could not find git-agy wrapper in the workspace paths.");
	process.exit(1);
}

function runGit(args: string[]): string {
	const res = spawnSync(gitWrapper, args, { encoding: "utf8" });
	if (res.status !== 0) {
		throw new Error(`Git command failed: ${args.join(" ")}\n${res.stderr}`);
	}
	return res.stdout.trim();
}

// 1. Find the last git tag
let lastTag = "";
try {
	lastTag = runGit(["describe", "--tags", "--abbrev=0"]);
} catch {
	try {
		// Fallback to the first commit if no tags exist
		lastTag = runGit(["rev-list", "--max-parents=0", "HEAD"]);
	} catch {
		lastTag = "";
	}
}

console.log(
	`ℹ️ Last release tag identified: ${lastTag || "None (starting fresh)"}`,
);

// 2. Extract commit logs since last tag
let commits: { hash: string; subject: string; body: string }[] = [];
if (lastTag) {
	const logOutput = runGit(["log", `${lastTag}..HEAD`, "--format=%H %s"]);
	if (logOutput) {
		commits = logOutput.split("\n").map((line) => {
			const firstSpace = line.indexOf(" ");
			const hash = line.slice(0, firstSpace);
			const subject = line.slice(firstSpace + 1);
			const body = runGit(["show", "-s", "--format=%b", hash]);
			return { hash, subject, body };
		});
	}
} else {
	const logOutput = runGit(["log", "--format=%H %s"]);
	if (logOutput) {
		commits = logOutput.split("\n").map((line) => {
			const firstSpace = line.indexOf(" ");
			const hash = line.slice(0, firstSpace);
			const subject = line.slice(firstSpace + 1);
			const body = runGit(["show", "-s", "--format=%b", hash]);
			return { hash, subject, body };
		});
	}
}

if (commits.length === 0) {
	console.log(
		"✅ No new commits since the last release. Skipping release generation.",
	);
	process.exit(0);
}

// 3. Determine the version bump type based on conventional commits
let bumpType: "major" | "minor" | "patch" = "patch";
let hasBreaking = false;
let hasFeat = false;
let hasFix = false;

for (const c of commits) {
	const isBreaking =
		c.subject.includes("!") || c.body.includes("BREAKING CHANGE");
	if (isBreaking) {
		hasBreaking = true;
		break;
	}
	if (c.subject.startsWith("feat")) {
		hasFeat = true;
	}
	if (c.subject.startsWith("fix") || c.subject.startsWith("perf")) {
		hasFix = true;
	}
}

if (hasBreaking) {
	bumpType = "major";
} else if (hasFeat) {
	bumpType = "minor";
} else if (hasFix) {
	bumpType = "patch";
} else {
	bumpType = "patch";
}

// 4. Calculate next semver version from package.json
const pkgPath = path.join(process.cwd(), "package.json");
if (!fs.existsSync(pkgPath)) {
	console.error("❌ package.json not found in the current directory.");
	process.exit(1);
}

const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
const currentVersion = pkg.version || "1.0.1";
const parts = currentVersion.split(".").map(Number);
if (parts.length < 3 || parts.some(Number.isNaN)) {
	console.error(
		`❌ Invalid current version format in package.json: ${currentVersion}`,
	);
	process.exit(1);
}

let nextVersion = "";
if (bumpType === "major") {
	nextVersion = `${parts[0] + 1}.0.0`;
} else if (bumpType === "minor") {
	nextVersion = `${parts[0]}.${parts[1] + 1}.0`;
} else {
	nextVersion = `${parts[0]}.${parts[1]}.${parts[2] + 1}`;
}

console.log(
	`🚀 Bumping version: ${currentVersion} ➡️ ${nextVersion} (${bumpType} release)`,
);

// 5. Categorize commits and build the Changelog
const categories: Record<string, string[]> = {
	Features: [],
	"Bug Fixes": [],
	Performance: [],
	Refactoring: [],
	Documentation: [],
	"Chores & Maintenance": [],
};

for (const c of commits) {
	const subj = c.subject;
	if (subj.startsWith("feat")) {
		categories["Features"]?.push(subj);
	} else if (subj.startsWith("fix")) {
		categories["Bug Fixes"]?.push(subj);
	} else if (subj.startsWith("perf")) {
		categories["Performance"]?.push(subj);
	} else if (subj.startsWith("refactor")) {
		categories["Refactoring"]?.push(subj);
	} else if (subj.startsWith("docs")) {
		categories["Documentation"]?.push(subj);
	} else {
		categories["Chores & Maintenance"]?.push(subj);
	}
}

const dateStr = new Date().toISOString().split("T")[0];
let releaseNotes = `## v${nextVersion} (${dateStr})\n\n`;

for (const [title, list] of Object.entries(categories)) {
	if (list.length > 0) {
		releaseNotes += `### ${title}\n`;
		for (const item of list) {
			releaseNotes += `- ${item}\n`;
		}
		releaseNotes += `\n`;
	}
}

// 6. Prepend release notes to CHANGELOG.md
const changelogPath = path.join(process.cwd(), "CHANGELOG.md");
let changelogContent = "";
if (fs.existsSync(changelogPath)) {
	changelogContent = fs.readFileSync(changelogPath, "utf8");
} else {
	changelogContent = "# Changelog\n\n";
}

const titleIndex = changelogContent.indexOf("# Changelog\n");
if (titleIndex !== -1) {
	const insertPoint = titleIndex + "# Changelog\n".length;
	changelogContent =
		changelogContent.slice(0, insertPoint) +
		"\n" +
		releaseNotes +
		changelogContent.slice(insertPoint);
} else {
	changelogContent = `# Changelog\n\n${releaseNotes}${changelogContent}`;
}

fs.writeFileSync(changelogPath, changelogContent, "utf8");
console.log("📝 CHANGELOG.md updated successfully.");

// 7. Update package.json version
pkg.version = nextVersion;
fs.writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`, "utf8");
console.log("📝 package.json version updated.");

// 8. Update hardcoded version in src/server.ts if it exists
const serverPath = path.join(process.cwd(), "src/server.ts");
if (fs.existsSync(serverPath)) {
	let serverContent = fs.readFileSync(serverPath, "utf8");
	serverContent = serverContent.replace(
		new RegExp(`version: "${currentVersion}"`, "g"),
		`version: "${nextVersion}"`,
	);
	fs.writeFileSync(serverPath, serverContent, "utf8");
	console.log("📝 src/server.ts hardcoded version strings updated.");
}

// 9. Git Add, Commit, Tag and Push
const filesToStage = ["package.json", "CHANGELOG.md"];
if (fs.existsSync(serverPath)) {
	filesToStage.push("src/server.ts");
}

for (const file of filesToStage) {
	runGit(["add", file]);
}

runGit(["commit", "-m", `chore(release): v${nextVersion} [skip ci]`]);
console.log("✅ Changes committed.");

runGit(["tag", "-a", `v${nextVersion}`, "-m", `Release v${nextVersion}`]);
console.log(`✅ Tag v${nextVersion} created.`);

const branchName = runGit(["branch", "--show-current"]) || "main";
runGit(["push", "origin", branchName]);
runGit(["push", "origin", `v${nextVersion}`]);
console.log("✈️ Release branch and tag successfully pushed to origin.");
