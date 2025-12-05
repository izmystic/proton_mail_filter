require ["fileinto", "regex", "envelope"];

/**
 * -----------------------------------------------------------------------------
 * SECTION: Updates & Development
 * DESCRIPTION: Filters software development notifications AND account security/
 * login alerts.
 * -----------------------------------------------------------------------------
 */
if anyof (
    /* 1. Infrastructure Check: Matches List-IDs and Senders for dev platforms */
    header :regex "list-id" "(github\\.com|gitlab\\.com|npmjs\\.org|stackoverflow\\.com|medium\\.com)",
    header :regex "from" "@(github\\.com|gitlab\\.com|npmjs\\.org|stackoverflow\\.com|medium\\.com)",

    /* 2. Keyword Check: Matches dev-specific terms AND account security terms. */
    /* FIX: Added missing security phrases for FB/Reddit/LinkedIn/Instagram */
    header :contains "subject" [
        "security alert",
        "security code",
        "access token",
        "pipeline",
        "merge request",
        "pull request",
        "password",
        "login",
        "log in",
        "steam guard",
        "verification",
        "verify",
        "recovery",
        "account",
        "confirm this email",
        "new device",
        "email removed",
        "email address has been changed",
        "your pin",
        "did you just"
    ]
) {
    fileinto "Updates";
    stop;
}

/**
 * -----------------------------------------------------------------------------
 * SECTION: Purchases & Finance
 * DESCRIPTION: Routes transactional emails (receipts, invoices) to the
 * "Purchases" folder.
 * -----------------------------------------------------------------------------
 */
if anyof (
    /* 1. Sender Check: Matches specific transactional domains in the 'From' header */
    header :regex "from" "@(paypal\\.com|stripe\\.com|square\\.com|amazon\\.com|ebay\\.com|shop\\.app|steampowered\\.com)",

    /* 2. Subject Check: Looks for specific billing keywords. */
    header :contains "subject" [
        "receipt",
        "order confirmation",
        "invoice",
        "payment processed",
        "billing statement"
    ]
) {
    fileinto "Purchases";
    stop;
}

/**
 * -----------------------------------------------------------------------------
 * SECTION: Social Media
 * DESCRIPTION: Routes notifications from major social platforms to the
 * "Social" folder.
 * -----------------------------------------------------------------------------
 */
if anyof (
    /* 1. List-ID Check: Matches standard mailing list IDs for social platforms */
    header :regex "list-id" "(facebook\\.com|twitter\\.com|linkedin\\.com|instagram\\.com|tiktok\\.com|pinterest\\.com|reddit\\.com|discordapp\\.com|twitch\\.tv|quora\\.com|nextdoor\\.com)",

    /* 2. Sender Check: Matches domains AND subdomains. */
    header :regex "from" "@(.*\\.)?(facebookmail\\.com|twitter\\.com|x\\.com|linkedin\\.com|instagram\\.com|tiktok\\.com|pinterest\\.com|snapchat\\.com|redditmail\\.com|reddit\\.com|discord\\.com|twitch\\.tv|youtube\\.com|quora\\.com|nextdoor\\.com|tumblr\\.com|medium\\.com)",

    /* 3. Context Check: Catches common social interaction keywords. */
    header :contains "subject" [
        "friend request",
        "tagged you",
        "mentioned you",
        "retweeted",
        "shared",
        "story",
        "login",
        "verification code",
        "new follower",
        "suggested",
        "digest",
        "community",
        "thread",
        "someone sent you",
        "new pin",
        "new snap"
    ]
) {
    fileinto "Social";
    stop;
}

/**
 * -----------------------------------------------------------------------------
 * SECTION: Forums & Mailing Lists
 * DESCRIPTION: Identifies generic mailing list traffic and bulk emails.
 * -----------------------------------------------------------------------------
 */
if anyof (
    /* 1. Platform Check: Matches common mailing list providers */
    header :regex "list-id" "(googlegroups\\.com|yahoogroups\\.com|listserv|mailinglist)",

    /* 2. Header Check: Looks for 'Precedence: bulk' or 'list' headers */
    header :contains "precedence" ["list", "bulk"],

    /* 3. Existence Check: Checks if the 'list-post' header exists */
    exists "list-post"
) {
    fileinto "Forums";
    stop;
}

/**
 * -----------------------------------------------------------------------------
 * SECTION: Promotions (Catch-All)
 * DESCRIPTION: Aggressive filtering for marketing emails, newsletters,
 * and discounts.
 * -----------------------------------------------------------------------------
 */
if anyof (
    /* 1. Sender Check: Matches known marketing automation domains */
    header :regex "from" "@(mailchimp\\.com|e\\.customeriomail\\.com|rsgsv\\.net)",

    /* 2. Heuristic Check: If it has an 'unsubscribe' link, it is likely a newsletter */
    exists "list-unsubscribe",

    /* 3. Keyword Check: Matches common sales terminology */
    header :contains "subject" [
        "sale",
        "discount",
        "limited time",
        "% off",
        "coupon",
        "clearance"
    ]
) {
    fileinto "Promotions";
    stop;
}
