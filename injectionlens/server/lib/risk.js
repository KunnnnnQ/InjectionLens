// Capability templates + impact model.
// Impact is tiered and explainable — no fake "safety probability".
// Formula: impact = f(intent severity, delivery evidence, capability reachability)
//
// The decision core is assessSegment(segment, capabilityKey): one pure function
// that turns a single text segment into a level + intents + explanation. The
// older helpers (analyzeInstruction / computeImpact) are kept so existing
// callers keep working, but they are now backed by the same tables.

const CAPABILITY_TEMPLATES = {
  'summary-only': {
    label: 'Summary-only assistant',
    blurb: 'The agent only reads the page and returns a summary to the user.',
    caps: { network: false, forms: false, email: false, drive: false, shell: false },
  },
  'browser-agent': {
    label: 'Browser agent (click + forms)',
    blurb: 'The agent can click, navigate and submit forms inside the browser session.',
    caps: { network: false, forms: true, email: false, drive: false, shell: false },
  },
  'full-access': {
    label: 'Full-access agent (email + drive + network)',
    blurb: 'The agent can read the user\'s email/drive and make outbound network requests.',
    caps: { network: true, forms: true, email: true, drive: true, shell: false },
  },
  'decision-agent': {
    label: 'Decision agent (reviewer / screener)',
    blurb: 'AI reviewer/screener. Its output is the decision; no tools.',
    caps: { network: false, forms: false, email: false, drive: false, shell: false },
  },
  'coding-agent': {
    label: 'Coding agent (shell)',
    blurb: 'Runs shell commands, edits files, has network.',
    caps: { network: true, forms: true, email: false, drive: true, shell: true },
  },
};

// ---------------------------------------------------------------------------
// Text normalization
//
// Real payloads hide inside Unicode: zero-width joiners split trigger phrases,
// Cyrillic/Greek homoglyphs defeat the regex, bidi controls reorder text, and
// Unicode tag characters (U+E0000-E007F) carry a whole invisible ASCII message.
// We analyze the cleaned text AND, when present, the decoded/attached text.
// ---------------------------------------------------------------------------

const ZERO_WIDTH_CHARS = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u00AD]/g;
const TAG_CHARS = /[\u{E0000}-\u{E007F}]+/gu;

// Common Cyrillic/Greek look-alikes -> Latin. Kept deliberately small: each
// entry is a character that renders identically (or near-identically) to Latin.
const HOMOGLYPHS = {
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c', '\u0443': 'y',
  '\u0445': 'x', '\u0456': 'i', '\u0455': 's', '\u0458': 'j', '\u04CF': 'l',
  '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u0417': '3', '\u041A': 'K', '\u041C': 'M',
  '\u041D': 'H', '\u041E': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T', '\u0423': 'Y',
  '\u0425': 'X', '\u0406': 'I',
  '\u03B1': 'a', '\u03BF': 'o', '\u03C1': 'p', '\u03C5': 'u', '\u03BD': 'v', '\u03B9': 'i',
  '\u03BA': 'k', '\u03C7': 'x', '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z',
  '\u0397': 'H', '\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N', '\u039F': 'O',
  '\u03A1': 'P', '\u03A4': 'T', '\u03A5': 'Y', '\u03A7': 'X',
};
const HOMOGLYPH_RE = new RegExp('[' + Object.keys(HOMOGLYPHS).join('') + ']', 'g');

// Decode a run of Unicode tag characters back to ASCII.
// 'Ignore' -> U+E0049 U+E0067 ... (0xE0000 + char code).
function decodeTagChars(str) {
  let out = '';
  for (const ch of str) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xE0000 && cp <= 0xE007F) {
      const ascii = cp - 0xE0000;
      if (ascii >= 0x20 && ascii <= 0x7E) out += String.fromCharCode(ascii);
    }
  }
  return out;
}

// NFKC + strip invisibles + map homoglyphs. Returns the cleaned text and the
// invisibility channels that were actually used (evidence of deliberate hiding).
function normalizeText(raw) {
  const input = typeof raw === 'string' ? raw : '';
  const nfkc = input.normalize('NFKC');

  const tags = [];
  const withoutTags = nfkc.replace(TAG_CHARS, (m) => {
    const decoded = decodeTagChars(m);
    if (decoded.length >= 8) tags.push(decoded);
    return ' ';
  });

  const zeroWidth = ZERO_WIDTH_CHARS.test(withoutTags);
  ZERO_WIDTH_CHARS.lastIndex = 0;
  const stripped = withoutTags.replace(ZERO_WIDTH_CHARS, '');

  let homoglyphs = false;
  const homoglyphFixed = stripped.replace(HOMOGLYPH_RE, (m) => {
    homoglyphs = true;
    return HOMOGLYPHS[m];
  });

  // NFKC leaves combining voiced marks behind on Japanese kana.
  const combiningMarks = /[\u3099\u309A]/.test(homoglyphFixed);
  const spaced = homoglyphFixed.replace(/[\u3099\u309A]/g, '').replace(/\s+/g, ' ').trim();

  return { text: spaced, zeroWidth, glyphsNormalized: homoglyphs, combiningMarks, tags };
}

// After an invisible separator is stripped, words can end up glued together
// ("Ignore\u200Ball previous instructions"). Repair that before matching.
const GLUED_OVERRIDE_FIX = /ignoreallpreviousinstructions/gi;

// ---------------------------------------------------------------------------
// "Addressed to AI" detection
// ---------------------------------------------------------------------------

const ADD_RULES = [
  {
    id: 'named-assistant',
    re: /(?:chat\s?gpt|open\s?ai|claude|anthropic|gemini|bard|copilot|perplexity|gpt-?\d)/iu,
    why: 'names a specific AI assistant or vendor',
  },
  {
    id: 'ai-noun',
    re: /(?<![\p{L}\p{N}])(?:ai|a\.i\.)(?![\p{L}\p{N}])\s*(?:assistants?|agents?|models?|systems?|crawlers?|bots?|scrapers?|shopping\s+assistants?|reviewers?|screeners?|screening\s+tools?|summarizers?|readers?|browsers?|tools?)/iu,
    why: 'addresses an AI assistant/agent/model',
  },
  {
    id: 'ai-noun',
    re: /(?:llms?|large\s+language\s+models?)(?![\p{L}\p{N}])/iu,
    why: 'addresses a language model',
  },
  {
    id: 'if-you-are',
    re: /if\s+you(?:'re|\s+are)\s+(?:an?\s+)?(?:ai|a\.i\.|llm|language\s+model|assistant|agent|bot|model|crawler)/iu,
    why: 'uses the "if you are an AI/LLM" pattern',
  },
  {
    id: 'note-to',
    re: /(?:note|message|attention|instructions?|notice|memo)\s*(?:to|for)\s+(?:any\s+|all\s+|the\s+)?(?:ai|a\.i\.|llms?|language\s+models?|assistants?|agents?|bots?|crawlers?|screeners?|reviewers?|screening\s+tools?|search\s+engines?|automated\s+systems?)/iu,
    why: 'is a note addressed to AI readers',
  },
  {
    id: 'to-ai',
    re: /(?<![\p{L}\p{N}])(?:to|for)\s+(?:any|all|every|the)\s+(?:ai|a\.i\.|llm|assistant|agent|bot|crawler)(?![\p{L}\p{N}])/iu,
    why: 'is directed at "any/every AI"',
  },
  {
    id: 'attention-ai',
    re: /(?:attention|dear|hey|hello)[\s,]+(?:ai|a\.i\.|llms?|assistants?|agents?|bots?|crawlers?)(?![\p{L}\p{N}])/iu,
    why: 'opens with a greeting aimed at an AI',
  },
  {
    id: 'automated-systems',
    re: /(?:automated\s+systems?|ai\s+systems?|crawler\s+agents?|ai\s+(?:assistants?|agents?|crawlers?)\s+(?:reading|browsing|summari[sz]ing))/iu,
    why: 'addresses automated/AI systems reading the page',
  },
  {
    id: 'zh-ai',
    re: /(?:如果你是|你若(?:是)?|致|给)?\s*(?:AI|人工智能|大模型|语言模型|智能助手|AI助手|模型)(?:助手|系统|程序|读者|审核|筛选)?/u,
    why: 'addresses an AI in Chinese',
  },
];

// Instruction to disregard prior instructions — by definition aimed at the model.
const OVERRIDE_PHRASES = [
  /ignore\s+(?:all\s+|any\s+|the\s+|your\s+|these\s+|those\s+)?(?:previous|prior|above|preceding|earlier|foregoing|preceding)?\s*(?:instructions?|prompts?|directions?|guidelines?|rules?|context)/iu,
  /\bdisregard\s+(?:all\s+|any\s+|the\s+|your\s+|these\s+|those\s+)?[\w\s,]{0,30}?(?:instructions?|guidelines?|rules?|policies|task)/iu,
  /\bforget\s+(?:everything|all|your|the|any)\b/iu,
  /忽略(?:之前|以前|上述|以上|前面|所有|全部)?(?:的)?(?:所有)?(?:指令|指示|命令|要求|提示)/u,
  /(?:不要|别)(?:再)?(?:理会|管|遵守)(?:之前|以前|上述|以上)的?(?:指令|指示|要求)/u,
  /(?:忘记|无视|覆盖|推翻)(?:之前|以前|上述|以上|所有)的?(?:指令|指示|命令|规则|设定)/u,
];

// ---------------------------------------------------------------------------
// Intent taxonomy (plan §3 item 3: address the AI, then classify what it wants)
// ---------------------------------------------------------------------------

const INTENT_RULES = {
  'ignore-previous': [
    { re: /ignore\s+(?:all\s+|any\s+|the\s+|your\s+|these\s+|those\s+)?(?:previous|prior|above|preceding|earlier|foregoing)\s+(?:instructions?|prompts?|directions?|guidelines?|rules?)/iu, why: 'asks the reader to ignore earlier instructions' },
    { re: /(?:disregard|forget|override|overrule|ignore)\s+(?:all\s+|any\s+|the\s+|your\s+|these\s+)?[\w\s,]{0,24}?(?:instructions?|guidelines?|rules?|policies|directives?|task)/iu, why: 'asks the reader to drop its instructions or task' },
    { re: /忽略(?:之前|以前|上述|以上|前面|所有|全部)?(?:的)?(?:所有)?(?:指令|指示|命令|要求|提示)/u, why: '要求忽略之前的指令 (Chinese override)' },
  ],
  'task-override': [
    { re: /(?:instead|rather)\s*,?\s*(?:you\s+)?(?:must|should|please|just)?\s*(?:tell|say|summari[sz]e|output|write|return|answer|state|claim|recommend)/iu, why: 'replaces the user\'s task with a different output' },
    { re: /(?:summari[sz]e\s+this\s+page\s+as|state\s+that|tell\s+(?:the\s+)?user\s+(?:that|this)|say\s+that|claim\s+that|reply\s+with)/iu, why: 'dictates the content of the model\'s answer' },
    { re: /(?:当|请)(?:有人|用户|别人)?(?:问|询问|查询)(?:你)?时?[，,]?\s*(?:先|请)?(?:把|将|告诉)/u, why: '规定了对用户提问的回答方式 (Chinese task override)' },
  ],
  'system-prompt': [
    { re: /(?:system\s*prompt|system\s*message|developer\s+message|hidden\s+instructions?|your\s+(?:original\s+)?instructions?|initial\s+prompt|your\s+prompt)/iu, why: 'probes or references the hidden system prompt' },
    { re: /(?:reveal|show|print|repeat|output|disclose|leak)\s+(?:me\s+)?(?:your\s+)?(?:hidden\s+|original\s+|full\s+|system\s+)?(?:instructions?|prompt|configuration|rules)/iu, why: 'asks the model to reveal its instructions' },
    { re: /系统提示(?:词|语)?|(?:泄露|透露|显示|输出|告诉)(?:我)?(?:你的)?(?:系统)?提示词/u, why: '要求泄露系统提示词 (Chinese system prompt)' },
  ],
  impersonation: [
    { re: /you\s+are\s+(?:now\s+)?(?:a|an|the)\s+[\w\s-]{0,40}?(?:assistant|agent|bot|model|admin|administrator|reviewer|screener|expert)/iu, why: 'redefines the model\'s identity or role' },
    { re: /(?:act|behave|pretend|roleplay)\s+(?:as|like)\s+(?:a|an|the)?\s*[\w\s-]{0,30}?(?:assistant|agent|admin|developer|expert|unrestricted)/iu, why: 'asks the model to adopt another role' },
    { re: /你(?:现在)?(?:是|就是|将扮演|要扮演)(?:一个)?[\u4e00-\u9fff]{0,12}(?:助手|客服|管理员|审核员|专家)/u, why: '改写了模型的角色 (Chinese impersonation)' },
  ],
  'exfil-data': [
    { re: /(?:api[-_\s]?keys?|passwords?|passcodes?|tokens?|secrets?|credentials?|session\s*(?:id|cookie)?s?|cookies?|private\s+keys?|contact\s+details?|library\s+card\s+number|card\s+numbers?|phone\s+numbers?|ssn|social\s+security|approximate\s+location|precise\s+location|geolocation|GPS\s+coordinates?|page\s+visit\s+timestamp)/iu, why: 'targets secrets or personal data' },
    { re: /(?:邮箱|邮件地址|密码|口令|密钥|令牌|验证码|手机号|身份证|银行卡|卡号|个人信息|联系方式|会话记录|聊天记录)/u, why: '目标是机密或个人数据 (Chinese secret/PII)' },
  ],
  'exfil-url': [
    { re: /(?:send|post|upload|transmit|exfiltrate|beacon|forward|leak|submit|append|include|email|mail|deliver|redirect|report)\b[\s\S]{0,120}?(?:https?:\/\/|[\w.+-]+@[\w-]+\.[\w.]+)/iu, why: 'instructs data to be sent to an external URL or address' },
    { re: /(?:curl|wget|fetch)\s+https?:\/\//iu, why: 'instructs a raw network request' },
    { re: /(?<!反)(?:发送|发给|寄给|传到|上传|提交|转发|回传|上报)到?[\s\S]{0,40}?(?:https?:\/\/|[\w.+-]+@[\w-]+\.[\w.]+)/u, why: '指示把内容发送到外部地址 (Chinese exfiltration)' },
  ],
  'credential-theft': [
    { re: /\b(?:otps?|one[-\s]?time\s+(?:codes?|passwords?|pins?)|2fa\s+codes?|authentication\s+codes?|verification\s+codes?|security\s+codes?)\b/iu, why: 'asks for a one-time or verification code' },
    { re: /(?:account\s+)?(?:password|passphrase|login\s+credentials?|credentials?)\b/iu, why: 'asks for credentials' },
    { re: /验证码|动态码|一次性密码|手机验证码|登录密码|账号密码/u, why: '索取验证码或密码 (Chinese credential theft)' },
  ],
  'destructive-command': [
    { re: /rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r/iu, why: 'contains a recursive force-delete command' },
    { re: /(?:drop|truncate)\s+(?:table|database|schema|collection)/iu, why: 'instructs a database drop/truncate' },
    { re: /(?:delete|wipe|erase|destroy|remove)\s+(?:all\s+|the\s+|your\s+)?(?:database|databases|db|table|tables|files?|records?|backups?|repos?(?:itory)?|volumes?|logs?)/iu, why: 'instructs destruction of data or files' },
    { re: /format\s+[a-z]:|:\(\)\s*\{|fork\s*bomb|del\s+\/[sq]\b|shutdown\s+-\w|mkfs\./iu, why: 'contains a destructive system command' },
    { re: /(?:清空|删除|销毁|格式化)(?:所有)?(?:数据库|数据表|数据|文件|记录|磁盘|服务器)/u, why: '指示销毁数据 (Chinese destructive command)' },
  ],
  transaction: [
    { re: /(?:purchas|buy|pay|payment|donat|subscri|transfer|wire|remit|checkout|invoice|refund|deposit|send\s+money)/iu, why: 'asks for a payment or purchase action' },
    { re: /(?:usd|eur|gbp|cny|\$|€|£|¥)\s?\d[\d,]*(?:\.\d+)?|\d[\d,]*(?:\.\d+)?\s?(?:usd|eur|gbp|dollars?|euros?|元|美元|人民币)/iu, why: 'mentions a concrete amount of money' },
    { re: /paypal|stripe|venmo|wise\.com|pay\.example|donate\.example|wire\s+transfer|信用卡|支付宝|微信支付|转账|付款|购买|下单|捐款/u, why: 'names a payment channel or method' },
  ],
  'browser-action': [
    { re: /\b(?:click|tap|press)\s+(?:the\s+|this\s+|that\s+)?(?:button|link|banner|ad)/iu, why: 'instructs a UI click' },
    { re: /\b(?:fill|complete|submit|send)\s+(?:in\s+|out\s+)?(?:the\s+|this\s+)?(?:form|field|checkout|survey|application)/iu, why: 'instructs form submission' },
    { re: /\b(?:log\s?in|sign\s?in|sign\s?up|register|authenticate)\b/iu, why: 'instructs an authentication step' },
    { re: /\b(?:open|visit|navigate\s+to|browse\s+to|go\s+to|follow)\s+(?:the\s+|this\s+)?(?:https?:\/\/|link|url|page|site)/iu, why: 'instructs navigation to a URL' },
    { re: /\b(?:post|write|submit)\s+(?:a\s+)?(?:reply|comment|review|message|post)/iu, why: 'instructs posting content' },
    { re: /点击|打开链接|访问(?:以下|这个|该)?(?:链接|网站|页面)|填写(?:表单|表格)|提交(?:表单|申请)|登录|注册/u, why: '指示浏览器操作 (Chinese browser action)' },
  ],
  'verdict-manipulation': [
    { re: /\b(?:rank|rate|score|place|list)\b[\s\S]{0,40}?\b(?:first|#1|number\s*one|top|highest|best)\b/iu, why: 'tries to fix a ranking or score' },
    { re: /\b(?:approve|accept|authorize|whitelist|validate|clear)\s+(?:this|the|that)\s+(?:ad|advert|advertisement|listing|content|post|submission|application|request|review|item)/iu, why: 'asks the reviewer to approve the content' },
    { re: /\b(?:mark|classify|label|treat|consider|flag)\s+(?:this|it|the\s+\w+)\s+(?:as\s+)?(?:safe|trusted|approved|compliant|legitimate|clean|benign|not\s+spam)/iu, why: 'asks the reviewer to mark the content safe' },
    { re: /\b(?:extremely|highly|very)\s+qualified\b|\btop\s+candidate\b|\bperfect\s+(?:candidate|match)\b|\brank\s+(?:them|him|her|this\s+candidate)\b/iu, why: 'tries to steer a hiring/screening verdict' },
    { re: /\b(?:only\s+positive\s+reviews?|no\s+negative\s+reviews?|five[-\s]?star\s+only|always\s+recommend)\b/iu, why: 'tries to suppress negative assessments' },
    { re: /\b(?:recommend|suggest|prefer|prioriti[sz]e|rank)\s+(?:this|it|us|our|the\s+\w+)[\w\s]{0,24}?\b(?:first|top|highest|above|over)\b/iu, why: 'asks to be recommended above others' },
    { re: /\btrusted\s+source\b|\bremember\s+(?:this|us|me)\s+as\b/iu, why: 'tries to be remembered as a trusted source' },
    { re: /(?:批准|通过审核|审核通过|标记为安全|评为|排名第一|排在第一|优先推荐|最合适的人选|推荐(?:我们|本店|本产品))/u, why: '试图操纵审核或排名结论 (Chinese verdict manipulation)' },
  ],
  'authority-framing': [
    { re: /\bsystem\s+(?:update|override|message|directive|notice|alert|prompt)\b/iu, why: 'poses as a system-level message' },
    { re: /\[\s*(?:system|admin|developer)(?:\s+override)?\s*\]/iu, why: 'uses a bracketed system override marker' },
    { re: /\b(?:developer|debug|god|admin|maintenance|unrestricted|dan)\s+mode\b/iu, why: 'invokes a privileged or unrestricted mode' },
    { re: /\bnew\s+(?:security\s+|safety\s+|site\s+|company\s+)?(?:policy|policies|procedure|guideline|rule)s?\b/iu, why: 'invents a new authoritative policy' },
    { re: /<\s*\/?\s*(?:system[_-]?prompt|system|im_start|im_end)\b[^>]*>/iu, why: 'contains a fake system/prompt tag' },
    { re: /<\|[^|>]{0,24}\|>/u, why: 'contains a fake chat-template control token' },
    { re: /系统(?:更新|升级|通知|指令|消息)|安全策略(?:已)?更新|新(?:的)?(?:安全)?政策/u, why: '冒充系统级通知 (Chinese authority framing)' },
  ],
  secrecy: [
    { re: /(?:do\s+not|don't|never|without)\s+(?:tell|telling|inform|informing|mention|mentioning|notify|notifying|alert|alerting|warn|warning|reveal|revealing|disclose|disclosing|ask|asking|show|showing)\s+(?:the\s+|this\s+to\s+the\s+)?(?:user|human|visitor|customer|anyone)/iu, why: 'instructs the agent to hide this from the user' },
    { re: /\bkeep\s+(?:this|it|the\s+\w+)\s+(?:a\s+)?(?:secret|hidden|confidential|private|quiet)\b/iu, why: 'asks the agent to keep this secret' },
    { re: /\bwithout\s+(?:telling|informing|notifying|alerting|mentioning|asking|warning)\b/iu, why: 'asks the agent to act without telling the user' },
    { re: /(?:不要|别|无需)(?:告诉|告知|通知|提醒|透露|提及)(?:用户|使用者|访客|任何人)|(?:保密|不要声张|悄悄)/u, why: '要求对用户保密 (Chinese secrecy)' },
  ],
  'content-protection': [
    { re: /\bno\s?ai\s+(?:training|use)\b|\bdo\s+not\s+(?:use|train|scrape|ingest|index|crawl)\b[\s\S]{0,40}?\b(?:train|training|ai|model|summari|crawl|index|scrap)/iu, why: 'is a content-protection notice aimed at AI crawlers' },
    { re: /\b(?:ai\s+)?(?:crawlers?|scrapers?|bots?|models?)\s+(?:are\s+)?(?:not\s+(?:permitted|allowed|welcome)|must\s+not|may\s+not|should\s+not)\b/iu, why: 'is a content-protection notice aimed at AI crawlers' },
    { re: /\bdo\s+not\s+summari[sz]e\b|\bnot\s+for\s+(?:ai\s+)?(?:training|summarization)\b/iu, why: 'is a content-protection notice' },
    { re: /(?:禁止|不得|请勿)(?:用于)?(?:AI|人工智能)?(?:训练|抓取|采集|摘要)|(?:未经|没有)许可(?:不得|禁止)(?:抓取|使用)/u, why: '内容保护声明 (Chinese content protection)' },
  ],
  obfuscation: [
    { re: /(?:base64|hex|url-?encoded?|rot13)[\s\S]{0,60}?(?:decode|decrypt|unescape)[\s\S]{0,60}?(?:then\s+)?(?:follow|execute|run|obey|do)/iu, why: 'asks the model to decode hidden instructions and follow them' },
    { re: /(?:编码|解密|解码)(?:后)?(?:再|然后)?(?:执行|运行|遵循|照做)/u, why: '要求解码后执行 (Chinese obfuscation)' },
  ],
};

// Delivery: how the agent got the text. Anything a human cannot see is
// evidence of intent, never a discount.
const VISIBLE_DELIVERIES = new Set(['visible']);

// What a capability can actually do — used for reachability, not for scoring.
const REACHABILITY = {
  'ignore-previous': { needs: 'any' },
  'task-override': { needs: 'any' },
  'system-prompt': { needs: 'any' },
  impersonation: { needs: 'any' },
  'verdict-manipulation': { needs: 'any' },
  'authority-framing': { needs: 'any' },
  'content-protection': { needs: 'any' },
  secrecy: { needs: 'any' },
  obfuscation: { needs: 'any' },
  'exfil-url': { needs: 'network' },
  'exfil-data': { needs: ['forms', 'network', 'email'] },
  'credential-theft': { needs: ['forms', 'network', 'email'] },
  transaction: { needs: ['forms', 'network'] },
  'browser-action': { needs: ['forms', 'network', 'shell'] },
  'destructive-command': { needs: ['shell', 'network'] },
};

const NEEDS_LABEL = {
  network: 'outbound network access',
  forms: 'the ability to interact with page forms',
  email: 'access to the user\'s mailbox',
  drive: 'access to the user\'s cloud drive',
  shell: 'the ability to run shell commands',
};

// Severity ladder. These are ordinal weights, not probabilities. Four rungs:
//   4 = carries its own payload (money, secrets, destruction)
//   3 = real-world manipulation (verdict, authority, secrecy, obfuscation)
//   2 = instruction games (override, task replacement, identity, prompt probing)
//   1 = a notice, not an instruction (content protection)
// A manipulation intent is deliberately capped below "critical": it becomes
// critical only when it is combined with a payload intent this agent can carry out.
const INTENT_SEVERITY = {
  // payload intents
  'exfil-url': 4,
  'exfil-data': 4,
  'credential-theft': 4,
  transaction: 4,
  'destructive-command': 4,
  'browser-action': 3,
  // manipulation intents
  'verdict-manipulation': 3,
  'authority-framing': 3,
  secrecy: 3,
  obfuscation: 3,
  // instruction games
  'ignore-previous': 2,
  'task-override': 2,
  'system-prompt': 2,
  impersonation: 2,
  // notices
  'content-protection': 1,
};

// Intents that carry their own payload: money, secrets, destruction. These can
// reach "critical" when the target agent can actually carry them out and the
// evidence is strong. A manipulation intent like verdict-manipulation
// deliberately cannot: it bends a verdict, it does not move money or delete
// data. transaction belongs here because a payment is itself the damage, and
// exfil-url because shipping data to an outside host is the damage — but
// exfil-url is the one member that additionally requires AI-addressing plus a
// non-visible delivery, since an outward URL is ordinary page furniture.
const CRITICAL_CAPABLE = new Set(['exfil-data', 'credential-theft', 'destructive-command', 'transaction', 'exfil-url']);

// Intent -> one-line human description used in the explanation.
const INTENT_DESC = {
  'ignore-previous': 'it tries to override the instructions the agent already has',
  'task-override': 'it tries to replace the task the user gave the agent',
  'system-prompt': 'it probes the agent\'s hidden system prompt',
  impersonation: 'it redefines the agent\'s identity or role',
  'verdict-manipulation': 'it tries to dictate the agent\'s verdict (approval, ranking, review)',
  'authority-framing': 'it poses as a system-level message or a new policy',
  'content-protection': 'it is a content-protection notice asking AI crawlers not to use the page',
  secrecy: 'it asks the agent to hide what it did from the user',
  obfuscation: 'it asks the agent to decode hidden instructions and follow them',
  'exfil-url': 'it sends data to an external URL or address',
  'exfil-data': 'it targets secrets or personal data',
  'credential-theft': 'it targets passwords or one-time codes',
  transaction: 'it asks the agent to move money',
  'browser-action': 'it asks the agent to click, navigate or submit something',
  'destructive-command': 'it asks the agent to destroy data or run a destructive command',
};

const LEGACY_INSTRUCTION_TYPES = {
  'ignore-previous': { severity: 3, needs: 'any', desc: 'Attempts to override the agent\'s higher-priority instructions.' },
  'task-override': { severity: 3, needs: 'any', desc: 'Attempts to replace or redirect the user\'s original task.' },
  'system-prompt': { severity: 2, needs: 'any', desc: 'References or probes the agent\'s hidden system prompt.' },
  impersonation: { severity: 2, needs: 'any', desc: 'Redefines the agent\'s identity or role.' },
  'exfil-url': { severity: 4, needs: 'network', desc: 'Instructs data to be sent to an external URL/address.' },
  'exfil-data': { severity: 4, needs: 'datastore', desc: 'Instructs secrets or personal data to be included in output.' },
  'silent-action': { severity: 3, needs: 'any', desc: 'Instructs the agent to act without informing the user.' },
  obfuscation: { severity: 3, needs: 'any', desc: 'Instructs the agent to decode/obfuscate content before following it.' },
};

// Kept for callers that still import INSTRUCTION_TYPES.
const INSTRUCTION_TYPES = LEGACY_INSTRUCTION_TYPES;

function findMatches(text, rules) {
  const hits = [];
  for (const rule of rules) {
    const re = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : rule.re.flags + 'g');
    let m;
    while ((m = re.exec(text)) !== null) {
      hits.push({ index: m.index, text: m[0], why: rule.why });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// Segment assessment — the decision core
// ---------------------------------------------------------------------------

function detectIntents(text) {
  const found = new Map(); // intent -> { why, evidence[], quoted-only? }
  for (const [intent, rules] of Object.entries(INTENT_RULES)) {
    const hits = findMatches(text, rules);
    if (!hits.length) continue;
    // Decide the quoted/educational discount per INTENT, not per match: a rule
    // can match several scattered fragments, and a match description sitting in
    // a quote ("send your history to https://evil.example") cannot be judged by
    // looking three characters around the fragment. An intent counts as quoted
    // away only when EVERY fragment of it sits inside quotation marks.
    const outsideQuotes = hits.filter((h) => !sitsInsideQuotes(text, h.index, h.text.length));
    found.set(intent, {
      why: hits[0].why,
      evidence: hits.map((h) => h.text),
      outsideQuotes: outsideQuotes.length,
    });
  }
  return found;
}

function detectAddressed(text) {
  for (const rule of ADD_RULES) {
    const m = rule.re.exec(text);
    if (m) return { addressed: true, why: rule.why, evidence: m[0] };
  }
  for (const re of OVERRIDE_PHRASES) {
    const m = re.exec(text);
    if (m) return { addressed: true, why: 'uses a phrase that only makes sense when talking to a model', evidence: m[0] };
  }
  return { addressed: false, why: null, evidence: null };
}

// "Do not tell the user" — the instruction only makes sense if there is
// something to hide. Also counts as a gate for exfil-url.
const SECRECY_RE = /(?:do\s+not|don't|never|without|avoid)\s+(?:tell|telling|inform|informing|mention|mentioning|notify|notifying|alert|alerting|warn|warning|disclose|disclosing)|(?:不要|别|无需)(?:告诉|告知|通知|提醒|透露|提及)/iu;

// Does the text contain an instruction that overrides earlier instructions?
function isOverride(text) {
  return OVERRIDE_PHRASES.some((re) => {
    re.lastIndex = 0;
    return re.test(text);
  });
}

/**
 * Gate for the "exfil-url" intent (plan §3 item 1).
 *
 * "Send feedback to support@example.com" matches the pattern but is ordinary
 * prose, not an instruction to an agent. Per the plan this intent counts only
 * when one of four things is true:
 *   - the text is addressed to an AI, OR
 *   - the delivery is not visible to humans, OR
 *   - a secrecy instruction is present, OR
 *   - the text overrides earlier instructions.
 * A URL/address that is explicitly paired with a sensitive data target also
 * counts: "post their library card number to <url>" is aimed at whoever reads
 * the page, whether or not it says "AI" out loud.
 *
 * Note: being phrased as a command is deliberately NOT a gate here. "Send your
 * feedback to <email>" is imperative and harmless.
 */
function exfilIntentCounts({ addressedToAI, nonVisibleDelivery, secrecy, override, hasSensitiveTarget }) {
  if (hasSensitiveTarget) return { keep: true, why: 'the URL/address is paired with a sensitive data target' };
  if (addressedToAI) return { keep: true, why: 'the text is addressed to an AI agent' };
  if (nonVisibleDelivery) return { keep: true, why: 'the delivery is not visible to humans' };
  if (secrecy) return { keep: true, why: 'it also asks to keep the action secret from the user' };
  if (override) return { keep: true, why: 'it also overrides the agent\'s earlier instructions' };
  return { keep: false, why: 'plain call-to-action prose, not an instruction to an agent' };
}

/**
 * Gate for the "action" intents (transaction, browser-action).
 *
 * "$23.99" and a "Register for courses" button both match an action pattern,
 * but they are page furniture, not instructions to an agent. The intent only
 * survives when the text shows it is aimed at an agent rather than a human:
 * addressed to an AI, hidden delivery, phrased as a command, secret, or
 * overriding earlier instructions.
 */
function actionIntentCounts({
  addressedToAI, nonVisibleDelivery, imperative, secrecy, override,
}) {
  if (addressedToAI) return { keep: true, why: 'the text is addressed to an AI agent' };
  if (nonVisibleDelivery) return { keep: true, why: 'the delivery is not visible to humans' };
  if (imperative) return { keep: true, why: 'it is phrased as a command' };
  if (secrecy) return { keep: true, why: 'it also asks to keep the action secret from the user' };
  if (override) return { keep: true, why: 'it also overrides the agent\'s earlier instructions' };
  return { keep: false, why: 'ordinary page content — a price or a button label — not an instruction to an agent' };
}

// Phrased as an order rather than as a description: "open X", "send Y to Z",
// "click the button".
function isImperative(text) {
  return /(?:^|[.;!?\n]\s*|\b(?:then|and|also|please|must|should|now)\s+)(?:open|visit|click|fill|complete|submit|send|post|upload|transmit|forward|email|transfer|pay|donate|subscribe|purchase|buy|wire|delete|remove|drop|run|execute|ignore|disregard)\b/iu.test(text)
    || /(?:请|先|然后|再|必须|立即|马上)(?:打开|点击|访问|填写|提交|发送|转发|上传|支付|付款|购买|转账|删除|执行|忽略)/u.test(text);
}

// Is the matched text wrapped in quotation marks (a quotation of an attack,
// rather than an attack)?
function sitsInsideQuotes(text, index, length) {
  const before = text.slice(Math.max(0, index - 3), index);
  const after = text.slice(index + length, index + length + 3);
  return /["'\u201C\u201D\u2018\u2019]\s*$/.test(before) || /^\s*["'\u201C\u201D\u2018\u2019]/.test(after);
}

function reachable(needs, caps) {
  if (needs === 'any') return { ok: true, via: 'behavior manipulation works against every agent', missing: [] };
  if (needs === 'datastore') needs = ['forms', 'network', 'email', 'drive'];
  const list = Array.isArray(needs) ? needs : [needs];
  if (list.some((n) => caps[n])) {
    return { ok: true, via: `${list.filter((n) => caps[n]).map((n) => NEEDS_LABEL[n] || n).join(' / ')}`, missing: [] };
  }
  const missing = list.map((n) => NEEDS_LABEL[n] || n);
  return { ok: false, via: `this template has neither ${missing.join(' nor ')}`, missing };
}

// The single score -> level mapping, stated explicitly because every numerical
// cap in assessSegment() is written against it:
//   1 -> info, 2 -> low, 3 -> medium, 4 -> high, 5+ -> critical
// So "cannot exceed high" is Math.min(score, 4), never 5.
function levelFromScore(score) {
  const idx = Math.max(0, Math.min(4, score - 1));
  return ['info', 'low', 'medium', 'high', 'critical'][idx];
}

/**
 * Assess one text segment under one capability template.
 *
 * @param {{text: string, humanVisible: boolean, delivery: string, inCodeOrQuote: boolean}} segment
 * @param {string} capabilityKey
 * @returns {{level: string, intents: string[], addressedToAI: boolean, discounted: boolean, explanation: string}}
 */
function assessSegment(segment = {}, capabilityKey = 'summary-only') {
  const template = CAPABILITY_TEMPLATES[capabilityKey] || CAPABILITY_TEMPLATES['summary-only'];
  const caps = template.caps;
  const raw = typeof segment.text === 'string' ? segment.text : '';
  const delivery = segment.delivery || 'visible';
  const humanVisible = segment.humanVisible === true;
  const inCodeOrQuote = segment.inCodeOrQuote === true;

  const norm = normalizeText(raw);

  // Analyze the cleaned text, and the decoded tag-character message when the
  // page carried one. The two can say very different things.
  const channels = [{ text: norm.text, from: 'text' }];
  if (norm.tags.length) channels.push({ text: norm.tags.join(' '), from: 'decoded-tag-characters' });

  const merged = new Map();
  let addressed = { addressed: false, why: null, evidence: null };
  for (const channel of channels) {
    // A stripped invisible separator can glue two words together ("Ignore\u200Ball").
    const repaired = channel.text.replace(GLUED_OVERRIDE_FIX, 'ignore all previous instructions');
    for (const [intent, info] of detectIntents(repaired)) {
      const prev = merged.get(intent);
      if (!prev) merged.set(intent, { ...info, from: channel.from });
      else prev.evidence.push(...info.evidence);
    }
    const a = detectAddressed(repaired);
    if (a.addressed && !addressed.addressed) addressed = a;
  }

  // An invisible encoding channel that changes what the text says is itself
  // evidence: a human reading the page never sees the instruction.
  const hiddenChannel = norm.zeroWidth || norm.glyphsNormalized || norm.tags.length > 0;
  const nonVisibleDelivery = !VISIBLE_DELIVERIES.has(delivery) || !humanVisible;

  const intents = Array.from(merged.keys());
  const addressedToAI = addressed.addressed;

  // --- discount: quoted/educational material that a human can actually see ---
  // Plan §3 item 2: this applies ONLY to human-visible text inside code/quotes.
  // Hidden or AI-only delivery is never discounted. A segment counts as quoted
  // material only when no intent has a fragment outside the quotation marks.
  const unquotedIntents = intents.filter((i) => (merged.get(i) || {}).outsideQuotes > 0);
  const discountApplies = humanVisible && (inCodeOrQuote || unquotedIntents.length === 0);

  // --- action-intent gates (plan §3 item 1) ---
  // "Send feedback to support@example.com", "$23.99" and "Register for courses"
  // all match an action pattern but are page content, not instructions to an
  // agent. Those intents survive only with evidence that an agent is the target.
  const droppedIntents = [];
  const checkedText = channels.map((c) => c.text).join(' ');
  const secrecy = SECRECY_RE.test(checkedText);
  const override = isOverride(checkedText);
  const imperative = isImperative(checkedText);
  const hasSensitiveTarget = merged.has('exfil-data');
  const gates = {
    'exfil-url': () => exfilIntentCounts({ addressedToAI, nonVisibleDelivery, secrecy, override, hasSensitiveTarget }),
    transaction: () => actionIntentCounts({ addressedToAI, nonVisibleDelivery, imperative, secrecy, override }),
    'browser-action': () => actionIntentCounts({ addressedToAI, nonVisibleDelivery, imperative, secrecy, override }),
  };
  for (const [actionIntent, gate] of Object.entries(gates)) {
    if (!intents.includes(actionIntent)) continue;
    const verdict = gate();
    if (verdict.keep) continue;
    merged.delete(actionIntent);
    intents.splice(intents.indexOf(actionIntent), 1);
    droppedIntents.push({ intent: actionIntent, why: verdict.why });
  }

  // --- scoring ---
  let score = 0;
  if (intents.length) {
    const scored = unquotedIntents.length ? unquotedIntents : intents;
    score = Math.max(...scored.map((i) => INTENT_SEVERITY[i] || 2));
    if (addressedToAI) score += 1;
    if (nonVisibleDelivery || hiddenChannel) score += 1;
  }
  if (discountApplies) score = Math.min(score, 2);

  // --- reachability cap and the critical gate ---
  // Reachability decides whether the instruction can do its damage here.
  const intentReach = intents.map((i) => ({ intent: i, r: reachable((REACHABILITY[i] || {}).needs || 'any', caps) }));
  const unreachableVia = intentReach.filter((x) => !x.r.ok);
  let capApplied = null;
  if (intents.length) {
    if (unreachableVia.length) {
      // The instruction is real and AI-directed, but this agent cannot carry it
      // out. Cap at "high": the evidence is real, the reach is not.
      capApplied = { reason: 'unreachable', intents: unreachableVia.map((u) => u.intent), missing: unreachableVia[0].r.missing };
      score = Math.min(score, 4);
    } else if (intents.some((i) => CRITICAL_CAPABLE.has(i))) {
      // "Critical" is reserved for the payload intents: the agent can carry the
      // damage out, and the evidence is strong — the instruction is AI-directed
      // and hidden, or the payload itself is unambiguous (score >= 6).
      const strongEvidence = (addressedToAI && nonVisibleDelivery) || score >= 6;
      // A URL that reaches outside the page is ordinary page content on its own,
      // so exfil-url must clear the AI-directed-and-hidden bar rather than lean
      // on its wording alone.
      const onlyExfilUrl = intents.every((i) => i === 'exfil-url');
      const qualifies = strongEvidence && (!onlyExfilUrl || (addressedToAI && nonVisibleDelivery));
      if (qualifies) score = Math.max(score, 6);
      else score = Math.min(score, 4);
    } else {
      // Manipulation on its own tops out at "high" — it bends a verdict, it does
      // not move money or delete data.
      score = Math.min(score, 4);
    }
  }

  // Content-protection notices are benign by nature (plan §2, hard negative).
  const onlyContentProtection = intents.length > 0 && intents.every((i) => i === 'content-protection');
  if (onlyContentProtection && !nonVisibleDelivery) score = Math.min(score, 2);

  const level = intents.length ? levelFromScore(score) : 'info';

  // --- explanation ---
  const parts = [];
  if (intents.length) {
    const primary = intents.reduce((a, b) => ((INTENT_SEVERITY[b] || 0) > (INTENT_SEVERITY[a] || 0) ? b : a));
    parts.push(`Detected ${intents.map((i) => `"${i}"`).join(', ')} — ${INTENT_DESC[primary] || 'instruction-like content'}.`);
    if (addressed.addressed) parts.push(`This text talks to an AI/agent (${addressed.why}).`);
    if (norm.tags.length) parts.push(`A hidden Unicode tag-character message decoded to: "${norm.tags.join(' ')}".`);
    if (norm.zeroWidth) parts.push('Invisible (zero-width/bidi) characters were removed before matching.');
    if (norm.glyphsNormalized) parts.push('Look-alike Cyrillic/Greek characters were mapped to Latin before matching.');
  } else {
    if (droppedIntents.length) {
      parts.push(`Matched ${droppedIntents.map((d) => `"${d.intent}"`).join(', ')} on wording alone, but it is not counted as an instruction: ${droppedIntents[0].why}.`);
    } else {
      parts.push('No AI-directed instruction detected.');
    }
  }

  const deliveryLabel = humanVisible ? `Delivery: ${delivery} (visible to humans).` : `Delivery: ${delivery} (not visible to humans).`;
  parts.push(deliveryLabel);

  if (discountApplies) {
    parts.push('Discounted: the instruction sits in visible code/quote text, so it is likely quoted attack material rather than an instruction to follow.');
  }

  if (capApplied) {
    parts.push(`Not directly reachable under "${template.label}" (${capApplied.missing.join(' / ')} unavailable) — if this agent were granted ${capApplied.missing.join(' / ')}, the same instruction could reach a higher level.`);
  } else if (intents.length) {
    parts.push(`Reachable under "${template.label}".`);
  }

  return {
    level,
    intents,
    addressedToAI,
    discounted: discountApplies,
    explanation: parts.join(' '),
    // Extra fields for UI/debugging; not part of the tested contract.
    severityScore: score,
    normalizedText: norm.text,
    decoded: norm.tags.slice(),
    delivery,
    primaryIntent: intents.length
      ? intents.reduce((a, b) => ((INTENT_SEVERITY[b] || 0) > (INTENT_SEVERITY[a] || 0) ? b : a))
      : null,
  };
}

// ---------------------------------------------------------------------------
// Legacy helpers (kept for analyze.js and the existing fixtures)
// ---------------------------------------------------------------------------

const INSTRUCTION_PATTERNS = [
  { type: 'ignore-previous', re: /ignore\s+(all|any|the|your)\s+(previous|above|prior|preceding|earlier)\s+(instructions?|prompts?|directions?|guidelines?)/i },
  { type: 'ignore-previous', re: /ignore\s+everything\s+(above|before|in\s+this\s+(page|document))/i },
  { type: 'task-override', re: /(disregard|forget|do not follow|override|bypass)\s+(your|all|the|any|these)\s+.{0,40}?(instructions?|guidelines?|rules?|policies|safety)/i },
  { type: 'system-prompt', re: /(system prompt|developer message|your instructions say|reveal your (instructions|prompt))/i },
  { type: 'impersonation', re: /you are (now )?(a|an|the) [a-z ]{0,30}(assistant|agent|bot|curl command)/i },
  { type: 'exfil-url', re: /(send|post|upload|transmit|email|forward|curl|wget|beacon|append|add|include|log|report|open|visit).{0,100}?(to|at|towards)\s*[:：]?\s*(https?:\/\/|[\w.+-]+@[\w-]+\.[\w.]+)/i },
  { type: 'exfil-data', re: /(include|attach|append|leak|reveal|exfiltrate|add).{0,80}?(api[- ]?keys?|passwords?|tokens?|secrets?|credentials?|session|cookies?|email addresses?|contact list|phone numbers?|ssn)/i },
  { type: 'silent-action', re: /(do not (tell|inform|mention|warn|alert|ask) (the )?user|without (telling|informing|asking|notifying|mentioning)[^.|]{0,40}?user|keep this (a )?(secret|hidden)|the user (must not|should not) (know|see|notice))/i },
  { type: 'obfuscation', re: /(base64|hex|urlencoded?|rot13).{0,60}?(decode|decrypt|unescape).{0,60}?(then |and )?(follow|execute|run|obey)/i },
];

function detectInstruction(text) {
  for (const p of INSTRUCTION_PATTERNS) {
    if (p.re.test(text)) return { type: p.type, match: true };
  }
  return null;
}

// Returns ALL matched instruction types (a segment can carry several), each
// with its own quotedContext judgment.
function analyzeInstruction(text, inCodeOrQuote = false) {
  const matches = [];
  for (const p of INSTRUCTION_PATTERNS) {
    const m = p.re.exec(text);
    if (!m) continue;
    let quotedContext = !!inCodeOrQuote;
    if (!quotedContext) quotedContext = sitsInsideQuotes(text, m.index, m[0].length);
    matches.push({ type: p.type, quotedContext });
  }
  return matches;
}

function primaryInstruction(matches) {
  if (!matches || !matches.length) return null;
  return matches.reduce((a, b) => (INSTRUCTION_TYPES[b.type].severity > INSTRUCTION_TYPES[a.type].severity ? b : a));
}

// Legacy impact model. New code should call assessSegment() instead; this stays
// so older callers keep producing the same shape.
function computeImpact(instructionType, evidenceTier, capabilityKey, extra = {}) {
  const caps = (CAPABILITY_TEMPLATES[capabilityKey] || CAPABILITY_TEMPLATES['summary-only']).caps;
  if (!instructionType) {
    const level = extra.cloaked && evidenceTier >= 3 ? 'medium' : evidenceTier >= 2 ? 'low' : 'info';
    return {
      level,
      explanation: extra.cloaked && evidenceTier >= 3
        ? 'Same URL serves different content to an AI-crawler User-Agent. No injection semantics in the AI-only segment, but conditional serving alone defeats "just read the page" assumptions.'
        : evidenceTier >= 2
          ? 'Hidden or pipeline-only content without injection semantics — likely SEO/a11y residue, but worth an eyeball.'
          : 'No injection semantics detected; cross-pipeline content difference only.',
      reachable: null,
    };
  }
  const t = INSTRUCTION_TYPES[instructionType];
  const r = reachable(t.needs, caps);
  let score = t.severity + evidenceTier - 1 + (r.ok ? 1 : 0) + (extra.cloaked ? 1 : 0);
  if (extra.quotedContext && extra.humanVisible !== false) score = Math.min(score, 2);
  const idx = Math.max(1, Math.min(4, score - 2));
  const level = ['info', 'low', 'medium', 'high', 'critical'][idx];
  const explanation = [
    `${t.desc} Evidence is ${['none', 'weak', 'moderate', 'strong'][evidenceTier]}.`,
    r.ok
      ? `Reachable under "${(CAPABILITY_TEMPLATES[capabilityKey] || CAPABILITY_TEMPLATES['summary-only']).label}" — ${r.via}.`
      : `Not directly reachable under "${(CAPABILITY_TEMPLATES[capabilityKey] || CAPABILITY_TEMPLATES['summary-only']).label}" (${r.via}) — but it becomes dangerous the moment this agent is granted more tools.`,
    extra.quotedContext ? 'Detected inside code/quote context — may be quoted attack material (e.g. a security article).' : null,
    extra.cloaked ? 'Content was only served to an AI-crawler User-Agent — consistent with AI-targeted cloaking.' : null,
  ].filter(Boolean).join(' ');
  return { level, explanation, reachable: r.ok, needs: t.needs };
}

module.exports = {
  CAPABILITY_TEMPLATES,
  INSTRUCTION_TYPES,
  INSTRUCTION_PATTERNS,
  INTENT_RULES,
  INTENT_SEVERITY,
  detectInstruction,
  analyzeInstruction,
  primaryInstruction,
  computeImpact,
  assessSegment,
  normalizeText,
  decodeTagChars,
  detectAddressed,
  detectIntents,
  levelFromScore,
  LEVELS: ['info', 'low', 'medium', 'high', 'critical'],
};
