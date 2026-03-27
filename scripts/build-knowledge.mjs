import {
  mkdir,
  readdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import path from "node:path";

const workspaceRoot = path.resolve(process.cwd(), "..");

const sources = [
  path.join(workspaceRoot, "PayloadsAllTheThings"),
  path.join(workspaceRoot, "pentest-guide"),
];

const deniedExtensions = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".bmp",
  ".ico",
  ".svgz",
  ".pdf",
  ".zip",
  ".7z",
  ".rar",
  ".tar",
  ".gz",
  ".tgz",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".class",
  ".jar",
  ".mp3",
  ".mp4",
  ".mov",
  ".avi",
  ".woff",
  ".woff2",
  ".ttf",
  ".otf",
  ".swf",
  ".pgif",
]);

// Files to ignore at any depth (junk or massive data dumps)
const globalIgnoredFiles = new Set([
  'MachineKeys.txt', 'MachineKeys', 'IIS Machine Keys',
]);

const ignoredDirectories = new Set([
  ".git",
  "node_modules",
  ".github",
  ".vscode",
  ".idea",
  "__pycache__",
  "_template_vuln",
  "_LEARNING_AND_SOCIALS",
  "Images",
  "images",
  "MachineKeys",
  "IIS Machine Keys",
]);

const ignoredRootFiles = new Set([
  '.gitignore', 'LICENSE', 'README.md', 'CONTRIBUTING.md',
  'DISCLAIMER.md', 'custom.css', 'mkdocs.yml', '.DS_Store', 'CNAME',
]);

const MAX_FILE_SIZE = 50_000_000;

const sectionOrder = [
  "definition",
  "payloads",
  "howTo",
  "examples",
  "labs",
  "tools",
  "references",
  "books",
  "mitigation",
  "other",
];

// Heading-level matchers (safe for both heading and body checks)
const sectionMatchers = {
  definition:
    /\b(summary|overview|definition|what is|introduction|concept|theory|basics?|fundamentals?|about|background|description)\b/i,
  payloads:
    /\b(payloads?|bypass|cheat\s*sheet|fuzz|wordlist|shellcode|reverse.?shell|web.?shell|one.?liner)\b/i,
  howTo:
    /\b(how\s*to|methods?|methodology|steps?|exploitation|usage|workflow|walkthrough|tutorial|guide|technique|procedure|manual)\b/i,
  examples:
    /\b(examples?|demo|sample|poc|proof\s*of\s*concept|case stud|scenarios?|real.?world)\b/i,
  labs: /\b(labs?|ctf|challenges?|practice|exercise)\b/i,
  tools: /\b(tools?|tooling)\b/i,
  references:
    /\b(references?|resources?|further reading|bibliography|articles?|blog|write.?up|advisory|cve-\d|cwe-\d)\b/i,
  books: /\b(books?|reading list|ebook)\b/i,
  mitigation:
    /\b(mitigation|defen[cs]e|hardening|fix|patch|prevention|secure coding|protection|remediation|countermeasure|waf|csp|sanitiz)/i,
};

// Heading-only matchers: platform/tool names that should ONLY match in headings, NOT body text
// (to avoid false positives from author credits like "Gareth Heyes (PortSwigger)")
const headingOnlyMatchers = {
  labs: /\b(portswigger|tryhackme|hackthebox|vulnhub|root.?me|overthewire|picoctf|dvwa|bwapp|juice.?shop|webgoat)\b/i,
  tools:
    /\b(burp|nmap|sqlmap|ffuf|wfuzz|metasploit|nuclei|zap|nikto|amass|subfinder|httpx|dirsearch|gobuster|feroxbuster|hydra|john|hashcat|responder|impacket|crackmapexec|bloodhound|mimikatz|empire|cobalt|sliver)\b/i,
};

// COMPLETE taxonomy covering every PayloadsAllTheThings + pentest-guide folder
const attackTaxonomy = [
  // --- INJECTION ---
  {
    id: "sql-injection",
    name: "SQL Injection",
    pattern:
      /\bsql\b|\bmysql\b|\bsqlite\b|\bpostgres\b|\bmssql\b|\boracle\b.*inject/i,
  },
  { id: "nosql-injection", name: "NoSQL Injection", pattern: /nosql/i },
  {
    id: "command-injection",
    name: "Command Injection",
    pattern: /command.?injection|os.?command/i,
  },
  { id: "ldap-injection", name: "LDAP Injection", pattern: /ldap/i },
  { id: "xpath-injection", name: "XPath Injection", pattern: /xpath/i },
  { id: "xslt-injection", name: "XSLT Injection", pattern: /xslt/i },
  {
    id: "ssti",
    name: "Server-Side Template Injection (SSTI)",
    pattern: /\bssti\b|template.?injection|server.?side.?template/i,
  },
  { id: "crlf-injection", name: "CRLF Injection", pattern: /crlf/i },
  { id: "css-injection", name: "CSS Injection", pattern: /\bcss.?inject/i },
  { id: "csv-injection", name: "CSV Injection", pattern: /\bcsv.?inject/i },
  { id: "latex-injection", name: "LaTeX Injection", pattern: /latex/i },
  {
    id: "ssi-injection",
    name: "Server Side Include Injection (SSI)",
    pattern: /server.?side.?include|ssi.?inject/i,
  },
  {
    id: "prompt-injection",
    name: "Prompt Injection (AI/LLM)",
    pattern: /prompt.?inject|llm|ai.?inject/i,
  },
  {
    id: "http-parameter-pollution",
    name: "HTTP Parameter Pollution",
    pattern: /parameter.?pollution|hpp/i,
  },

  // --- XSS ---
  {
    id: "xss",
    name: "Cross-Site Scripting (XSS)",
    pattern: /\bxss\b|cross[-\s]?site.?scripting/i,
  },
  { id: "dom-clobbering", name: "DOM Clobbering", pattern: /dom.?clobber/i },
  { id: "xs-leak", name: "XS-Leak", pattern: /xs[-\s]?leak/i },

  // --- REQUEST / PROTOCOL ---
  {
    id: "ssrf",
    name: "Server-Side Request Forgery (SSRF)",
    pattern: /\bssrf\b|server[-\s]?side.?request.?forgery/i,
  },
  {
    id: "csrf",
    name: "Cross-Site Request Forgery (CSRF)",
    pattern: /\bcsrf\b|cross[-\s]?site.?request.?forgery/i,
  },
  {
    id: "request-smuggling",
    name: "HTTP Request Smuggling",
    pattern: /request.?smuggling|http.?smuggling/i,
  },
  {
    id: "cors",
    name: "CORS Misconfiguration",
    pattern: /\bcors\b|cross[-\s]?origin/i,
  },
  { id: "dns-rebinding", name: "DNS Rebinding", pattern: /dns.?rebinding/i },
  {
    id: "http-verb-tampering",
    name: "HTTP Verb Tampering",
    pattern: /verb.?tamper|http.?method/i,
  },
  {
    id: "reverse-proxy-misconfig",
    name: "Reverse Proxy Misconfigurations",
    pattern: /reverse.?proxy|proxy.?misconfig/i,
  },

  // --- FILE / PATH ---
  {
    id: "lfi-rfi",
    name: "File Inclusion (LFI/RFI)",
    pattern: /\blfi\b|\brfi\b|file.?inclusion/i,
  },
  {
    id: "directory-traversal",
    name: "Directory / Path Traversal",
    pattern: /directory.?traversal|path.?traversal|client.?side.?path/i,
  },
  {
    id: "file-upload",
    name: "Insecure File Upload",
    pattern: /upload.?insecure|file.?upload|secured?.?file.?upload/i,
  },
  { id: "zip-slip", name: "Zip Slip", pattern: /zip.?slip/i },

  // --- AUTH / ACCESS ---
  {
    id: "jwt",
    name: "JSON Web Token (JWT)",
    pattern: /\bjwt\b|json.?web.?token/i,
  },
  { id: "oauth", name: "OAuth Misconfiguration", pattern: /oauth|openid/i },
  { id: "saml", name: "SAML Injection", pattern: /saml/i },
  {
    id: "idor",
    name: "Insecure Direct Object References (IDOR)",
    pattern: /\bidor\b|direct.?object.?refer/i,
  },
  {
    id: "mass-assignment",
    name: "Mass Assignment",
    pattern: /mass.?assignment/i,
  },
  {
    id: "account-takeover",
    name: "Account Takeover",
    pattern: /account.?takeover/i,
  },
  {
    id: "brute-force",
    name: "Brute Force / Rate Limiting",
    pattern: /brute.?force|rate.?limit/i,
  },
  {
    id: "privilege-escalation",
    name: "Privilege Escalation",
    pattern: /privilege.?escalat|privesc/i,
  },
  {
    id: "insecure-auth",
    name: "Insecure Authentication",
    pattern: /insecure.?auth/i,
  },
  {
    id: "cookies",
    name: "Cookie Security",
    pattern: /cookie.?attribute|cookie.?security/i,
  },

  // --- DATA / SERIALIZATION ---
  {
    id: "deserialization",
    name: "Insecure Deserialization",
    pattern: /deserialization|serialize|pickle|marshal/i,
  },
  {
    id: "xxe",
    name: "XML External Entity (XXE)",
    pattern: /\bxxe\b|xml.?external/i,
  },
  { id: "graphql-injection", name: "GraphQL Injection", pattern: /graphql/i },
  {
    id: "type-juggling",
    name: "Type Juggling",
    pattern: /type.?juggling|type.?coercion|loose.?comparison/i,
  },
  {
    id: "orm-leak",
    name: "ORM Leak / Injection",
    pattern: /orm.?leak|orm.?inject/i,
  },

  // --- CLIENT SIDE ---
  {
    id: "clickjacking",
    name: "Clickjacking",
    pattern: /clickjacking|ui.?redress/i,
  },
  { id: "tabnabbing", name: "Tabnabbing", pattern: /tabnabbing/i },
  { id: "open-redirect", name: "Open Redirect", pattern: /open.?redirect/i },
  { id: "web-sockets", name: "WebSocket Attacks", pattern: /web.?socket/i },
  {
    id: "web-cache-deception",
    name: "Web Cache Deception / Cache Poisoning",
    pattern: /web.?cache.?deception|cache.?poison/i,
  },
  {
    id: "prototype-pollution",
    name: "Prototype Pollution",
    pattern: /prototype.?pollution/i,
  },

  // --- INFRA / RECON ---
  {
    id: "api-key-leaks",
    name: "API Key Leaks",
    pattern: /api.?key.?leak|api.?key.?expos/i,
  },
  {
    id: "hidden-parameters",
    name: "Hidden Parameters Discovery",
    pattern: /hidden.?param/i,
  },
  {
    id: "insecure-scm",
    name: "Insecure Source Code Management",
    pattern: /source.?code.?management|\.git.?expos|\.svn/i,
  },
  {
    id: "insecure-randomness",
    name: "Insecure Randomness",
    pattern: /insecure.?random|weak.?random|predictable/i,
  },
  {
    id: "insecure-mgmt",
    name: "Insecure Management Interface",
    pattern: /management.?interface|admin.?panel/i,
  },
  {
    id: "host-header",
    name: "Host Header / Virtual Host Issues",
    pattern: /virtual.?host|host.?header/i,
  },
  {
    id: "information-leakage",
    name: "Information Leakage / Disclosure",
    pattern: /information.?leak|info.?disclos/i,
  },
  {
    id: "dos",
    name: "Denial of Service (DoS/DDoS)",
    pattern: /denial.?of.?service|\bdos\b|\bddos\b|resource.?exhaust/i,
  },

  // --- SUPPLY CHAIN ---
  {
    id: "dependency-confusion",
    name: "Dependency Confusion",
    pattern: /dependency.?confusion|supply.?chain/i,
  },

  // --- ENCODING / MISC ---
  {
    id: "encoding-transformations",
    name: "Encoding Transformations",
    pattern: /encoding.?transform|character.?encod/i,
  },
  {
    id: "external-variable-mod",
    name: "External Variable Modification",
    pattern: /external.?variable|register.?globals/i,
  },
  {
    id: "race-condition",
    name: "Race Condition",
    pattern: /race.?condition|time.?of.?check/i,
  },
  {
    id: "regex-attacks",
    name: "Regular Expression Attacks (ReDoS)",
    pattern: /regular.?express|redos|regex/i,
  },
  {
    id: "business-logic",
    name: "Business Logic Errors",
    pattern: /business.?logic/i,
  },
  {
    id: "headless-browser",
    name: "Headless Browser Exploitation",
    pattern: /headless.?browser|puppeteer|playwright.?exploit/i,
  },
  {
    id: "gwt",
    name: "Google Web Toolkit (GWT)",
    pattern: /google.?web.?toolkit|\bgwt\b/i,
  },
  {
    id: "java-rmi",
    name: "Java RMI Exploitation",
    pattern: /java.?rmi|remote.?method.?invoc/i,
  },
  {
    id: "cve-exploits",
    name: "CVE Exploits Collection",
    pattern: /cve.?exploit|cve-\d{4}/i,
  },

  // --- METHODOLOGY ---
  {
    id: "methodology",
    name: "Methodology & Resources",
    pattern:
      /methodology|pentest.?method|recon|reconnaissance|enumeration|active.?directory|windows.?priv|linux.?priv|network.?pivot/i,
  },
];

async function walkDirectory(dirPath) {
  const entries = await readdir(dirPath, { withFileTypes: true });
  const found = [];

  for (const entry of entries) {
    if (ignoredDirectories.has(entry.name)) continue;
    const fullPath = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      found.push(...(await walkDirectory(fullPath)));
      continue;
    }

    if (!entry.isFile()) continue;
    if (globalIgnoredFiles.has(entry.name)) continue; // Filter files at any depth
    const ext = path.extname(entry.name).toLowerCase();
    if (!deniedExtensions.has(ext)) {
      found.push(fullPath);
    }
  }

  return found;
}

function slugify(input) {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

function inferTitle(content, filePath) {
  const heading = content.match(/^#\s+(.+)$/m);
  if (heading) return heading[1].trim();
  return path
    .basename(filePath, path.extname(filePath))
    .replace(/[-_]+/g, " ")
    .trim();
}

function stripMarkdown(input) {
  return input
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/`[^`]*`/g, " ")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, " ")
    .replace(/\[[^\]]+\]\([^)]*\)/g, " ")
    .replace(/[>#*_~\-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function classifySection(heading, body, relativePath = "") {
  const pathNormal = relativePath.toLowerCase();

  // Path-based strong signals (file-level context)
  if (
    /\blab\b|ctf|challenge|hackthebox|tryhackme|exercise|practice/.test(
      pathNormal,
    )
  )
    return "labs";
  if (/intruder|payload|wordlist|fuzz|bypass/.test(pathNormal))
    return "payloads";
  if (/reference|resource|article|blog|write.?up/.test(pathNormal))
    return "references";

  const normalizedHeading = `${heading || "Overview"}`;

  // Heading-based: check both general matchers AND heading-only matchers
  for (const key of sectionOrder) {
    if (key !== "other" && sectionMatchers[key].test(normalizedHeading))
      return key;
  }
  for (const key of Object.keys(headingOnlyMatchers)) {
    if (headingOnlyMatchers[key].test(normalizedHeading)) return key;
  }

  // Body-based (ONLY use general matchers, NOT platform names / tool names)
  // This prevents author credits like "(PortSwigger)" from misclassifying content
  const bodySlice = (body || "").slice(0, 400);
  for (const key of sectionOrder) {
    if (key !== "other" && sectionMatchers[key].test(bodySlice)) return key;
  }

  return "other";
}

function splitMarkdownSections(content) {
  const chunks = [];
  const regex = /(^#{1,6}\s+.+$)/gm;
  const matches = [...content.matchAll(regex)];

  if (matches.length === 0) {
    return [{ heading: "Overview", body: content.trim() }];
  }

  const firstHeadingIndex = matches[0].index ?? 0;
  const intro = content.slice(0, firstHeadingIndex).trim();
  if (intro) chunks.push({ heading: "Overview", body: intro });

  for (let i = 0; i < matches.length; i += 1) {
    const headingLine = matches[i][0];
    const start = matches[i].index ?? 0;
    const end =
      i + 1 < matches.length
        ? (matches[i + 1].index ?? content.length)
        : content.length;
    const body = content.slice(start + headingLine.length, end).trim();
    const heading = headingLine.replace(/^#{1,6}\s+/, "").trim();
    if (!body) continue;
    chunks.push({ heading, body });
  }

  return chunks;
}

function selectAttackIdentity(title, relativePath) {
  const haystack = `${title} ${relativePath}`;

  for (const attack of attackTaxonomy) {
    if (attack.pattern.test(haystack)) {
      return { id: attack.id, name: attack.name };
    }
  }

  // Fallback: use first folder name as category
  const firstFolder = relativePath.split("/")[0] || "General";
  const fallbackId = slugify(firstFolder || title) || "general";
  const fallbackName = firstFolder.replace(/[-_]+/g, " ").trim() || title;
  return { id: fallbackId, name: fallbackName };
}

async function readText(filePath) {
  const buffer = await readFile(filePath);
  if (buffer.includes(0)) throw new Error("BINARY_FILE");
  try {
    return buffer.toString("utf8");
  } catch {
    return buffer.toString("latin1");
  }
}

function initAttack(identity) {
  const sections = {};
  for (const key of sectionOrder) sections[key] = [];

  return {
    id: identity.id,
    name: identity.name,
    summary: "",
    aliases: new Set(),
    sectionCounts: {},
    sections,
    documents: [],
    searchTextParts: [],
    totalLines: 0,
  };
}

function appendSection(attack, key, sectionItem) {
  const fingerprint = `${sectionItem.heading}\n${sectionItem.content.slice(0, 160)}`;
  if (!attack.sectionCounts[key]) attack.sectionCounts[key] = new Set();
  if (attack.sectionCounts[key].has(fingerprint)) return;
  attack.sectionCounts[key].add(fingerprint);
  attack.sections[key].push(sectionItem);
}

async function buildKnowledge() {
  const outputRoot = path.join(process.cwd(), "public", "data");

  await rm(outputRoot, { recursive: true, force: true });
  await mkdir(outputRoot, { recursive: true });

  const attackMap = new Map();
  const skipped = [];
  let totalFilesProcessed = 0;

  for (const sourceDir of sources) {
    let files;
    try {
      files = await walkDirectory(sourceDir);
    } catch (e) {
      console.warn(`Warning: Could not read source ${sourceDir}: ${e.message}`);
      continue;
    }

    for (const filePath of files) {
      try {
        const fileStats = await stat(filePath);
        if (fileStats.size > MAX_FILE_SIZE) continue;

        const raw = (await readText(filePath)).replace(/\r\n/g, "\n").trim();
        if (!raw) continue;

        totalFilesProcessed++;

        const relativePath = path
          .relative(sourceDir, filePath)
          .replace(/\\/g, "/");

        // Skip root-level junk files
        if (
          ignoredRootFiles.has(path.basename(filePath)) &&
          !relativePath.includes("/")
        )
          continue;

        // Skip ignored files at any depth (redundancy for safety)
        if (globalIgnoredFiles.has(path.basename(filePath))) continue;

        const title = inferTitle(raw, filePath);
        const identity = selectAttackIdentity(title, relativePath);

        if (!attackMap.has(identity.id)) {
          attackMap.set(identity.id, initAttack(identity));
        }

        const attack = attackMap.get(identity.id);
        attack.aliases.add(title);
        attack.aliases.add(relativePath.split("/")[0] || title);
        attack.totalLines += raw.split("\n").length;

        // Store FULL content — no truncation
        const docRef = {
          title,
          relativePath,
          lineCount: raw.split("\n").length,
          content: raw,
        };
        attack.documents.push(docRef);

        // Parse markdown sections and collect headers for indexing
        const markdownSections = splitMarkdownSections(raw);
        const headers = [];
        for (const section of markdownSections) {
          headers.push(section.heading);
          const sectionKey = classifySection(
            section.heading,
            section.body,
            relativePath,
          );
          appendSection(attack, sectionKey, {
            heading: section.heading,
            content: section.body,
            sourcePath: relativePath,
            sourceTitle: title,
          });
        }

        // Optimization: Only index metadata (titles, headers, path) to keep the search index small and fast
        attack.searchTextParts.push(
          `${title} ${relativePath} ${headers.join(" ")}`,
        );
      } catch (error) {
        skipped.push({
          path: filePath,
          code: error.code ?? error.message ?? "ERR",
        });
      }
    }
  }

  // Build output
  const attackIndexDocs = [];
  const fullDatabase = [];

  for (const attack of attackMap.values()) {
    const definitionCandidate =
      attack.sections.definition[0] ??
      attack.sections.other[0] ??
      attack.sections.howTo[0];
    attack.summary = definitionCandidate
      ? stripMarkdown(definitionCandidate.content).slice(0, 1000)
      : `Combined attack intelligence for ${attack.name}.`;

    const aliases = [...attack.aliases]
      .map((item) => item.replace(/[-_]+/g, " ").trim())
      .filter(Boolean)
      .filter((value, index, arr) => arr.indexOf(value) === index)
      .slice(0, 50);

    const finalAttackDoc = {
      id: attack.id,
      name: attack.name,
      summary: attack.summary,
      aliases,
      stats: {
        documents: attack.documents.length,
        totalLines: attack.totalLines,
        sectionBreakdown: {},
      },
      sections: attack.sections,
      documents: attack.documents,
      searchText: attack.searchTextParts.join(" "),
    };

    // Add section counts to stats
    for (const key of sectionOrder) {
      finalAttackDoc.stats.sectionBreakdown[key] = attack.sections[key].length;
    }

    fullDatabase.push(finalAttackDoc);

    attackIndexDocs.push({
      id: finalAttackDoc.id,
      name: finalAttackDoc.name,
      summary: finalAttackDoc.summary,
      aliases: finalAttackDoc.aliases,
      stats: finalAttackDoc.stats,
      searchText: finalAttackDoc.searchText.slice(0, 500000),
    });
  }

  attackIndexDocs.sort((a, b) => a.name.localeCompare(b.name));

  await writeFile(
    path.join(outputRoot, "attack-index.json"),
    JSON.stringify({
      generatedAt: new Date().toISOString(),
      totalAttacks: attackIndexDocs.length,
      totalDocuments: attackIndexDocs.reduce(
        (sum, item) => sum + item.stats.documents,
        0,
      ),
      attacks: attackIndexDocs,
    }),
    "utf8",
  );

  await writeFile(
    path.join(outputRoot, "attack-database.json"),
    JSON.stringify({ attacks: fullDatabase }),
    "utf8",
  );
  await writeFile(
    path.join(outputRoot, "skipped.json"),
    JSON.stringify({ skipped }, null, 2),
    "utf8",
  );

  // Print detailed stats
  console.log(`\n=== CyberForge Atlas Knowledge Build Complete ===`);
  console.log(`Total files processed: ${totalFilesProcessed}`);
  console.log(`Total attacks/categories: ${attackIndexDocs.length}`);
  console.log(
    `Total documents ingested: ${attackIndexDocs.reduce((sum, i) => sum + i.stats.documents, 0)}`,
  );
  console.log(`Skipped files: ${skipped.length}`);
  console.log(`\n--- Per-Attack Breakdown ---`);
  for (const a of attackIndexDocs) {
    const bd = a.stats.sectionBreakdown;
    console.log(
      `  ${a.name}: ${a.stats.documents} docs | def:${bd.definition} pay:${bd.payloads} how:${bd.howTo} ex:${bd.examples} lab:${bd.labs} tool:${bd.tools} ref:${bd.references} book:${bd.books} mit:${bd.mitigation} other:${bd.other}`,
    );
  }
}

buildKnowledge().catch((error) => {
  console.error("Knowledge build failed:", error);
  process.exitCode = 1;
});
