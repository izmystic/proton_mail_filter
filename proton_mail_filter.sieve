require ["fileinto", "regex"];

/**
 * -----------------------------------------------------------------------------
 * SECTION: Updates & Development
 * DESCRIPTION: Filters software development notifications AND account security/
 * login alerts.
 * -----------------------------------------------------------------------------
 */
if anyof (
    header :regex "list-id" "(github\\.com|gitlab\\.com|npmjs\\.org|stackoverflow\\.com)",
    header :regex "from" "@(github\\.com|gitlab\\.com|npmjs\\.org|stackoverflow\\.com)",

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
        "sign-in",
        "sign in",
        "steam guard",
        "verification",
        "verify",
        "recovery",
        "new device",
        "confirm this email",
        "email removed",
        "email address has been changed",
        "email address has been added",
        "your pin",
        "did you just",
        "logged in",
        "trusted device",
        "passkey",
        "two-factor authentication",
        "2-step verification",
        "sign-in attempt",
        "unusual activity",
        "suspicious activity",
        "unauthorized access",
        "account suspended",
        "account locked",
        "account compromised",
        "account blocked",
        "account deactivated",
        "account limited",
        "account warning"
    ]
) {
    fileinto "Updates";
    stop;
}

/**
 * -----------------------------------------------------------------------------
 * SECTION: Purchases & Finance
 * DESCRIPTION: Routes transactional emails (receipts, invoices, shipping) to
 * the "Purchases" folder.
 * -----------------------------------------------------------------------------
 */
if anyof (
    header :regex "from" "@(paypal\\.com|stripe\\.com|square\\.com|amazon\\.com|ebay\\.com|shop\\.app|steampowered\\.com|venmo\\.com|etsy\\.com|walmart\\.com|target\\.com|bestbuy\\.com|newegg\\.com)",

    header :contains "subject" [
        "receipt",
        "order confirmation",
        "your order",
        "order has been",
        "out for delivery",
        "tracking number",
        "invoice",
        "payment processed",
        "payment failed",
        "payment confirmation",
        "billing statement",
        "transaction history",
        "refund",
        "subscription renewed",
        "subscription canceled",
        "subscription cancelled",
        "membership has been canceled"
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
    header :regex "list-id" "(facebook\\.com|twitter\\.com|linkedin\\.com|instagram\\.com|tiktok\\.com|pinterest\\.com|reddit\\.com|discordapp\\.com|twitch\\.tv|quora\\.com|nextdoor\\.com|threads\\.net|bsky\\.app)",

    header :regex "from" "@(.*\\.)?(facebookmail\\.com|twitter\\.com|x\\.com|linkedin\\.com|instagram\\.com|tiktok\\.com|pinterest\\.com|snapchat\\.com|redditmail\\.com|reddit\\.com|discord\\.com|twitch\\.tv|youtube\\.com|quora\\.com|nextdoor\\.com|tumblr\\.com|medium\\.com|cfx\\.re|threads\\.net|bsky\\.app)",

    header :contains "subject" [
        "friend request",
        "tagged you",
        "mentioned you",
        "retweeted",
        "new follower",
        "started following",
        "liked your",
        "commented on",
        "replied to",
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
    header :regex "list-id" "(googlegroups\\.com|yahoogroups\\.com|listserv|mailinglist)",
    header :contains "precedence" ["list", "bulk"],
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
    header :regex "from" "@(mailchimp\\.com|e\\.customeriomail\\.com|rsgsv\\.net)",
    exists "list-unsubscribe",
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
